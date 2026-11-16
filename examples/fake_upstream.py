#!/usr/bin/env python3
"""A stand-in for the model API, for the demo: answers every call with 18 tokens
and prints which key it was handed."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        print("upstream got key: %s" % self.headers.get("x-api-key"), flush=True)
        body = json.dumps({"type": "message", "content": [{"type": "text", "text": "ok"}],
                           "usage": {"input_tokens": 11, "output_tokens": 7}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
