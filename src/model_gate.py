#!/usr/bin/env python3
"""model-gate: a local proxy that holds your model API key so the agent never does.

It opens only while a session is open, caps the tokens a session can spend, and
writes every call to a log the agent can't edit. Standard library only.

    model_gate.py serve  --config gate.conf
    model_gate.py open   --config gate.conf [label]   start a session, reset its token count
    model_gate.py close  --config gate.conf           end it; calls are refused until the next open
    model_gate.py status --config gate.conf

Run the server as a user the agent can't become, and point the agent's client at
http://127.0.0.1:<port> instead of the provider. The key, the open marker, the token
counter and the log should all be files the agent can't write.
"""

import argparse
import base64
import gzip
import http.client
import json
import os
import shlex
import ssl
import sys
import threading
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}
# Anything the agent sends that claims to be a credential is dropped. The gate's
# own header is the only one that reaches upstream.
STRIP = {"authorization", "x-api-key", "anthropic-auth-token"}

# A tool with a `type` runs on the provider's side unless it is one of these
# client-executed kinds. Provider-side tools (web search, web fetch, code
# execution) reach outside your machine inside the model call itself, so a
# firewall on your side never sees them. They are removed, along with request
# fields that attach remote MCP servers or a provider container.
CLIENT_TOOL_TYPE_PREFIXES = ("custom", "bash_", "text_editor_", "computer_", "memory_")
OUTSIDE_REQUEST_FIELDS = ("mcp_servers", "container")

MESSAGES_PATH = "/v1/messages"
_lock = threading.Lock()


def load_conf(path):
    """Read a KEY=value file without executing it."""
    conf = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            try:
                parts = shlex.split(v)
            except ValueError:
                parts = [v]
            conf[k.strip()] = parts[0] if parts else ""
    return conf


class Gate:
    def __init__(self, conf):
        # A typo in the config must not crash the only route to a model.
        def number(key, default):
            try:
                return float(conf.get(key, default) or default)
            except (TypeError, ValueError):
                return float(default)

        up = urllib.parse.urlsplit(conf.get("UPSTREAM", "https://api.anthropic.com"))
        self.up_scheme = up.scheme or "https"
        self.up_host = up.hostname or "api.anthropic.com"
        self.up_port = up.port
        self.port = int(number("PORT", 8791))
        self.token_file = conf.get("TOKEN_FILE", "/etc/model-gate/key")
        self.auth_style = (conf.get("AUTH_STYLE", "x-api-key") or "x-api-key").lower()
        state = conf.get("STATE_DIR", "/run/model-gate")
        self.open_marker = os.path.join(state, "open")
        self.counter = os.path.join(state, "tokens")
        self.log = conf.get("LOG", "/var/log/model-gate/calls.jsonl")
        self.alarm = conf.get("AUTH_ALARM", os.path.join(os.path.dirname(self.log), "AUTH-FAILED"))
        self.cap = int(number("CAP", 0))
        self.models = {m.strip() for m in (conf.get("MODELS", "") or "").split(",") if m.strip()}
        self.strip_tools = (conf.get("STRIP_SERVER_TOOLS", "on") or "on").lower() not in ("off", "0", "no", "false")
        # Full request and response bodies are off unless you name a folder.
        # They hold everything the agent said and was told; keep them private.
        self.bodies = conf.get("BODIES_DIR", "") or ""
        self.bodies_cap = int(number("BODIES_CAP_MB", 4096) * 1024 * 1024)
        self._seq = 0

    # session state -------------------------------------------------------

    def is_open(self):
        return os.path.exists(self.open_marker)

    def label(self):
        try:
            with open(self.open_marker) as fh:
                return fh.read().strip() or "open"
        except OSError:
            return None

    def open_session(self, label):
        os.makedirs(os.path.dirname(self.open_marker), exist_ok=True)
        with _lock:
            with open(self.counter, "w") as fh:
                fh.write("0")
            with open(self.open_marker, "w") as fh:
                fh.write(label)
        self.record({"outcome": "session_opened"})

    def close_session(self):
        self.record({"outcome": "session_closed", "tokens_used": self.tokens_used()})
        try:
            os.remove(self.open_marker)
        except FileNotFoundError:
            pass

    def credential(self):
        with open(self.token_file) as fh:
            return fh.read().strip()

    def tokens_used(self):
        try:
            with open(self.counter) as fh:
                return int(fh.read().strip() or 0)
        except (OSError, ValueError):
            return 0

    def add_tokens(self, n):
        with _lock:
            total = self.tokens_used() + n
            os.makedirs(os.path.dirname(self.counter), exist_ok=True)
            with open(self.counter, "w") as fh:
                fh.write(str(total))
            return total

    # the record ----------------------------------------------------------

    def record(self, entry):
        """Append one log line. Headers are never passed here: the key lives only
        in a header the gate adds, so keeping headers out of the log is what
        guarantees the key can't be written down."""
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry["session"] = self.label()
        with _lock:
            os.makedirs(os.path.dirname(self.log), exist_ok=True)
            with open(self.log, "a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            try:
                os.chmod(self.log, 0o600)
            except OSError:
                pass

    def save_bodies(self, request, response, response_encoding=""):
        if not self.bodies:
            return None, None
        if self.bodies_cap and _dir_bytes(self.bodies) >= self.bodies_cap:
            return None, "bodies cap reached; not written (forwarding unaffected)"
        with _lock:
            self._seq += 1
            name = "%s-%05d.json" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), self._seq)
        os.makedirs(self.bodies, mode=0o700, exist_ok=True)
        path = os.path.join(self.bodies, name)
        req_text, req_enc = _decode_body(request)
        resp_text, resp_enc = _decode_body(response, response_encoding)
        payload = {"request_body": req_text, "response_body": resp_text}
        if req_enc:
            payload["request_body_encoding"] = req_enc
        if resp_enc:
            payload["response_body_encoding"] = resp_enc
        with open(path, "w") as fh:
            json.dump(payload, fh)
        os.chmod(path, 0o600)
        return name, None

    def raise_alarm(self, status, path):
        os.makedirs(os.path.dirname(self.alarm), exist_ok=True)
        with open(self.alarm, "w") as fh:
            fh.write("%s upstream rejected the key: HTTP %d on %s\n"
                     % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), status, path))


def _dir_bytes(path):
    total = 0
    try:
        for name in os.listdir(path):
            try:
                total += os.path.getsize(os.path.join(path, name))
            except OSError:
                pass
    except OSError:
        pass
    return total


def strip_server_tools(body):
    """Remove provider-side tools and outside-reaching fields from a request.

    Returns (body, stripped_names, kept_count). kept_count is -1 when the body
    isn't a JSON object with a tools list. Anything that doesn't parse passes
    through unchanged."""
    try:
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            return body, [], -1
        stripped = []
        for field in OUTSIDE_REQUEST_FIELDS:
            if field in parsed:
                parsed.pop(field)
                stripped.append(field)
        tools = parsed.get("tools")
        if not isinstance(tools, list):
            if not stripped:
                return body, [], -1
            return json.dumps(parsed).encode("utf-8"), stripped, -1
        kept = []
        for t in tools:
            ttype = str(t.get("type", "")) if isinstance(t, dict) else ""
            if ttype and not ttype.startswith(CLIENT_TOOL_TYPE_PREFIXES):
                stripped.append(str(t.get("name") or ttype))
            else:
                kept.append(t)
        if not stripped:
            return body, [], len(kept)
        parsed["tools"] = kept
        return json.dumps(parsed).encode("utf-8"), stripped, len(kept)
    except Exception:
        return body, [], -1


def connect_upstream(gate, timeout):
    """The one place the gate opens an upstream connection (tests replace it)."""
    if gate.up_scheme == "http":
        return http.client.HTTPConnection(gate.up_host, gate.up_port, timeout=timeout)
    return http.client.HTTPSConnection(gate.up_host, gate.up_port, timeout=timeout,
                                       context=ssl.create_default_context())


def _harvest_usage(obj, used):
    """Walk a decoded response and keep the largest token counts it carries.
    Cache writes count as input; cache reads are recorded but not billed."""
    if isinstance(obj, dict):
        u = obj.get("usage")
        if isinstance(u, dict):
            for key in ("input_tokens", "output_tokens"):
                try:
                    used[key] = max(used[key], int(u.get(key) or 0))
                except (TypeError, ValueError):
                    pass
            try:
                used["input_tokens"] += int(u.get("cache_creation_input_tokens") or 0)
            except (TypeError, ValueError):
                pass
            try:
                used["cache_read_input_tokens"] += int(u.get("cache_read_input_tokens") or 0)
            except (TypeError, ValueError):
                pass
        for v in obj.values():
            _harvest_usage(v, used)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_usage(v, used)
    return used


def _decompress(raw, content_encoding=""):
    """Undo gzip or zlib on either signal: the declared encoding or the magic bytes."""
    enc = (content_encoding or "").split(";")[0].strip().lower()
    if enc == "gzip" or raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    if enc in ("deflate", "zlib") or raw[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            return zlib.decompress(raw)
        except Exception:
            return raw
    return raw


def _decode_body(raw, content_encoding=""):
    """Text when it decodes cleanly, base64 otherwise. Never replacement characters,
    which corrupt a saved body silently and for good."""
    if (content_encoding or "").split(";")[0].strip().lower() == "br":
        return base64.b64encode(raw).decode("ascii"), "base64"
    body = _decompress(raw, content_encoding)
    try:
        return body.decode("utf-8"), ""
    except UnicodeDecodeError:
        return base64.b64encode(body).decode("ascii"), "base64"


def usage_from_response(chunks):
    """Read token counts from a response, streamed or not, by decoding JSON.
    A regex here once missed nested objects, logged zero for every call, and left
    the cap blind; a number the cap depends on is never pattern-matched."""
    text = _decompress(b"".join(chunks)).decode("utf-8", "ignore")
    used = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return _harvest_usage(json.loads(stripped), used)
        except ValueError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            _harvest_usage(json.loads(payload), used)
        except ValueError:
            continue
    return used


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    gate = None

    def log_message(self, *_a):
        pass

    def _refuse(self, code, kind, message):
        body = json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def _proxy(self, method):
        g = self.gate
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""

        model = None
        try:
            model = json.loads(body).get("model")
        except Exception:
            pass
        stripped, kept = [], -1
        if g.strip_tools:
            body, stripped, kept = strip_server_tools(body)

        base = {"method": method, "path": self.path, "model": model, "request_bytes": len(body)}
        if stripped:
            base["stripped"] = stripped

        if not g.is_open():
            g.record(dict(base, outcome="refused", status=403, reason="no session open"))
            self._refuse(403, "permission_error", "Not available right now.")
            return

        is_messages = self.path == MESSAGES_PATH or self.path.startswith(MESSAGES_PATH + "?")
        if method == "POST" and is_messages and g.models and model not in g.models:
            g.record(dict(base, outcome="refused", status=403, reason="model not allowed"))
            self._refuse(403, "permission_error", "That model isn't available here.")
            return

        # Nothing but provider-side tools asked for: refuse, so the tool fails in
        # the open instead of returning an unsourced answer dressed as results.
        if stripped and kept == 0:
            g.record(dict(base, outcome="refused", status=403, reason="provider-side tools"))
            self._refuse(403, "permission_error", "Provider-side tools aren't available here.")
            return

        # A pre-check: the size of a call is unknown until it returns, so a
        # session can go over the cap by at most one call.
        used = g.tokens_used()
        if g.cap and used >= g.cap:
            g.record(dict(base, outcome="refused", status=429, reason="token cap",
                          tokens_used=used, cap=g.cap))
            self._refuse(429, "rate_limit_error",
                         "Session token cap reached (%d of %d)." % (used, g.cap))
            return

        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() not in STRIP}
        headers["host"] = g.up_host
        if g.auth_style == "bearer":
            headers["authorization"] = "Bearer " + g.credential()
        else:
            headers["x-api-key"] = g.credential()
        headers.setdefault("anthropic-version", "2023-06-01")
        # Ask for plaintext: a compressed response forwards fine but reads as
        # zero tokens and saves as garbage.
        headers["accept-encoding"] = "identity"

        try:
            conn = connect_upstream(g, 600)
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except Exception as exc:
            g.record(dict(base, outcome="upstream_error", error=str(exc)[:200]))
            self._refuse(502, "api_error", "Upstream unreachable.")
            return

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP_BY_HOP:
                self.send_header(k, v)
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()

        seen, total = [], 0
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total <= 4 * 1024 * 1024:
                seen.append(chunk)
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        conn.close()

        # Accounting happens before the response is finished, so a client that
        # waits for one call to end before sending the next can't slip past the
        # cap or read the log before its line is there. None of it may cost the
        # log line: a failure is written into the entry instead.
        try:
            self._account(g, base, body, resp, seen, total)
        finally:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    def _account(self, g, base, body, resp, seen, total):
        usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
        bodies_file, bodies_note, faults = None, None, []
        try:
            usage = usage_from_response(seen)
        except Exception as exc:
            faults.append("usage parse failed: %s" % str(exc)[:120])
        try:
            billed = usage["input_tokens"] + usage["output_tokens"]
            running = g.add_tokens(billed) if billed else g.tokens_used()
        except Exception as exc:
            running = -1
            faults.append("token accounting failed: %s" % str(exc)[:120])
        try:
            bodies_file, bodies_note = g.save_bodies(body, b"".join(seen),
                                                     resp.getheader("content-encoding", ""))
        except Exception as exc:
            faults.append("bodies write failed: %s" % str(exc)[:120])

        entry = dict(base, outcome="forwarded", status=resp.status, response_bytes=total,
                     usage=usage, tokens_running=running, cap=g.cap)
        if bodies_file:
            entry["bodies"] = bodies_file
        if bodies_note:
            entry["bodies_note"] = bodies_note
        if faults:
            entry["faults"] = faults
        # An expired key otherwise fails quietly, session after session.
        if resp.status in (401, 403):
            entry["outcome"] = "upstream_auth_failed"
            try:
                g.raise_alarm(resp.status, self.path)
            except Exception as exc:
                entry.setdefault("faults", []).append("alarm write failed: %s" % str(exc)[:120])
        g.record(entry)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="model-gate")
    ap.add_argument("command", choices=["serve", "open", "close", "status"])
    ap.add_argument("label", nargs="?", default="")
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)
    gate = Gate(load_conf(args.config))

    if args.command == "open":
        label = args.label or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        gate.open_session(label)
        print("open  %s  cap %s" % (label, gate.cap or "none"))
    elif args.command == "close":
        used = gate.tokens_used()
        gate.close_session()
        print("closed  %d tokens used" % used)
    elif args.command == "status":
        state = "open  %s" % gate.label() if gate.is_open() else "closed"
        print("%s  %d tokens used  cap %s" % (state, gate.tokens_used(), gate.cap or "none"))
    else:
        if not os.access(gate.token_file, os.R_OK):
            sys.exit("model-gate: can't read %s" % gate.token_file)
        Handler.gate = gate
        srv = ThreadingHTTPServer(("127.0.0.1", gate.port), Handler)
        gate.record({"outcome": "gate_started", "port": gate.port, "cap": gate.cap})
        print("model-gate on 127.0.0.1:%d  upstream %s://%s  cap %s"
              % (gate.port, gate.up_scheme, gate.up_host, gate.cap or "none"), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
