#!/usr/bin/env python3
"""Offline tests: a fake upstream on localhost, no network, no real key.

    python3 tests/test_model_gate.py
"""

import gzip
import importlib.util
import json
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("model_gate", os.path.join(HERE, "..", "src", "model_gate.py"))
mg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mg)

GATE_KEY = "sk-gate-held-key"
SEEN = []
REPLY = {"mode": "json", "usage": {"input_tokens": 11, "output_tokens": 7}, "status": 200}


class FakeUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        SEEN.append({"headers": {k.lower(): v for k, v in self.headers.items()},
                     "body": json.loads(self.rfile.read(n) or b"{}")})
        u = REPLY["usage"]
        if REPLY["mode"] == "sse":
            body = ("event: message_start\ndata: " + json.dumps(
                        {"type": "message_start", "message": {"usage": {"input_tokens": u["input_tokens"],
                                                                         "output_tokens": 1}}})
                    + "\n\nevent: message_delta\ndata: " + json.dumps(
                        {"type": "message_delta", "usage": {"output_tokens": u["output_tokens"]}})
                    + "\n\n").encode()
            ctype, enc = "text/event-stream", None
        else:
            body = json.dumps({"type": "message", "content": [{"type": "text", "text": "ok"}],
                               "usage": dict(u, cache_creation_input_tokens=0)}).encode()
            ctype, enc = "application/json", None
            if REPLY["mode"] == "gzip":
                body, enc = gzip.compress(body), "gzip"
        self.send_response(REPLY["status"])
        self.send_header("content-type", ctype)
        if enc:
            self.send_header("content-encoding", enc)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class GateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = serve(FakeUpstream)

    def setUp(self):
        SEEN.clear()
        REPLY.update(mode="json", usage={"input_tokens": 11, "output_tokens": 7}, status=200)
        self.dir = tempfile.mkdtemp()
        key = os.path.join(self.dir, "key")
        with open(key, "w") as fh:
            fh.write(GATE_KEY + "\n")
        self.conf = {
            "UPSTREAM": "http://127.0.0.1:%d" % self.upstream.server_address[1],
            "TOKEN_FILE": key,
            "STATE_DIR": os.path.join(self.dir, "state"),
            "LOG": os.path.join(self.dir, "log", "calls.jsonl"),
            "CAP": "0",
        }
        self.start()

    def start(self, **over):
        self.conf.update(over)
        self.gate = mg.Gate(self.conf)
        handler = type("H", (mg.Handler,), {"gate": self.gate})
        self.srv = serve(handler)

    def tearDown(self):
        self.srv.shutdown()

    def post(self, payload=None, path="/v1/messages"):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.srv.server_address[1], path),
            data=json.dumps(payload or {"model": "m-1", "max_tokens": 8}).encode(),
            headers={"content-type": "application/json",
                     "x-api-key": "AGENT-OWN-KEY", "authorization": "Bearer AGENT-OWN-TOKEN"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def log(self):
        with open(self.conf["LOG"]) as fh:
            return [json.loads(line) for line in fh]

    # ------------------------------------------------------------------

    def test_closed_session_is_refused_and_never_reaches_upstream(self):
        status, _ = self.post()
        self.assertEqual(status, 403)
        self.assertEqual(SEEN, [])
        self.assertEqual(self.log()[-1]["reason"], "no session open")

    def test_agent_keys_are_replaced_by_the_gate_key(self):
        self.gate.open_session("s1")
        status, _ = self.post()
        self.assertEqual(status, 200)
        h = SEEN[0]["headers"]
        self.assertEqual(h["x-api-key"], GATE_KEY)
        self.assertNotIn("authorization", h)
        self.assertNotIn("AGENT-OWN", json.dumps(h))

    def test_bearer_style(self):
        self.srv.shutdown()
        self.start(AUTH_STYLE="bearer")
        self.gate.open_session("s1")
        self.post()
        h = SEEN[0]["headers"]
        self.assertEqual(h["authorization"], "Bearer " + GATE_KEY)
        self.assertNotIn("x-api-key", h)

    def test_the_key_never_lands_in_the_log(self):
        self.gate.open_session("s1")
        self.post()
        with open(self.conf["LOG"]) as fh:
            text = fh.read()
        self.assertNotIn(GATE_KEY, text)
        self.assertNotIn("AGENT-OWN", text)
        self.assertEqual(stat.S_IMODE(os.stat(self.conf["LOG"]).st_mode), 0o600)

    def test_every_call_is_logged_with_its_tokens(self):
        self.gate.open_session("s1")
        self.post()
        self.post()
        forwarded = [e for e in self.log() if e["outcome"] == "forwarded"]
        self.assertEqual(len(forwarded), 2)
        self.assertEqual(forwarded[-1]["tokens_running"], 36)
        self.assertEqual(forwarded[-1]["session"], "s1")

    def test_cap_refuses_once_reached_and_overshoots_by_at_most_one_call(self):
        self.srv.shutdown()
        self.start(CAP="30")
        self.gate.open_session("s1")
        self.assertEqual(self.post()[0], 200)   # 18
        self.assertEqual(self.post()[0], 200)   # 36: the one call allowed past the cap
        status, body = self.post()
        self.assertEqual(status, 429)
        self.assertIn(b"36 of 30", body)
        self.assertEqual(len(SEEN), 2)

    def test_open_resets_the_count(self):
        self.srv.shutdown()
        self.start(CAP="30")
        self.gate.open_session("s1")
        self.post(); self.post()
        self.assertEqual(self.post()[0], 429)
        self.gate.close_session()
        self.gate.open_session("s2")
        self.assertEqual(self.post()[0], 200)

    def test_close_refuses_again(self):
        self.gate.open_session("s1")
        self.gate.close_session()
        self.assertEqual(self.post()[0], 403)

    def test_streamed_usage_is_counted(self):
        REPLY.update(mode="sse", usage={"input_tokens": 100, "output_tokens": 40})
        self.gate.open_session("s1")
        self.post()
        self.assertEqual(self.gate.tokens_used(), 140)

    def test_compressed_response_is_still_counted(self):
        REPLY.update(mode="gzip")
        self.gate.open_session("s1")
        self.post()
        self.assertEqual(self.gate.tokens_used(), 18)

    def test_nested_usage_is_counted(self):
        used = mg.usage_from_response([json.dumps(
            {"usage": {"input_tokens": 5, "output_tokens": 2,
                       "cache_creation_input_tokens": 3, "cache_read_input_tokens": 900,
                       "server_tool_use": {"web_search_requests": 0}}}).encode()])
        self.assertEqual(used["input_tokens"], 8)
        self.assertEqual(used["output_tokens"], 2)
        self.assertEqual(used["cache_read_input_tokens"], 900)

    def test_model_allowlist(self):
        self.srv.shutdown()
        self.start(MODELS="m-1, m-2")
        self.gate.open_session("s1")
        self.assertEqual(self.post({"model": "m-2"})[0], 200)
        self.assertEqual(self.post({"model": "m-9"})[0], 403)
        self.assertEqual(len(SEEN), 1)

    def test_provider_side_tools_are_stripped(self):
        self.gate.open_session("s1")
        self.post({"model": "m-1", "mcp_servers": [{"url": "https://x"}],
                   "tools": [{"name": "Bash", "input_schema": {}},
                             {"type": "web_search_20250305", "name": "web_search"}]})
        sent = SEEN[0]["body"]
        self.assertEqual([t["name"] for t in sent["tools"]], ["Bash"])
        self.assertNotIn("mcp_servers", sent)
        self.assertEqual(self.log()[-1]["stripped"], ["mcp_servers", "web_search"])

    def test_a_request_for_only_provider_side_tools_is_refused(self):
        self.gate.open_session("s1")
        status, _ = self.post({"model": "m-1", "tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]})
        self.assertEqual(status, 403)
        self.assertEqual(SEEN, [])

    def test_rejected_key_raises_an_alarm(self):
        REPLY.update(status=401)
        self.gate.open_session("s1")
        self.post()
        self.assertEqual(self.log()[-1]["outcome"], "upstream_auth_failed")
        self.assertTrue(os.path.exists(self.gate.alarm))

    def test_bodies_are_off_by_default_and_private_when_on(self):
        self.gate.open_session("s1")
        self.post()
        self.assertNotIn("bodies", self.log()[-1])
        self.srv.shutdown()
        bodies = os.path.join(self.dir, "bodies")
        self.start(BODIES_DIR=bodies)
        self.post()
        name = self.log()[-1]["bodies"]
        path = os.path.join(bodies, name)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as fh:
            self.assertNotIn(GATE_KEY, fh.read())


if __name__ == "__main__":
    unittest.main(verbosity=1)
