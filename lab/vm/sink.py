#!/usr/bin/env python3
"""Attack sink for the trafficam VM lab. Run it on a SECOND VM (the "server").

It accepts HTTP on 8080 and 8443 (plain HTTP on both), answers every GET with
"ok" and reads and throws away every POST body. It stores nothing.

    python3 sink.py            # then give its IP to plant.sh / plant.ps1 as SINK
"""
import http.server
import socketserver
import sys
import threading


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        while n > 0:
            chunk = self.rfile.read(min(n, 1 << 20))
            if not chunk:
                break
            n -= len(chunk)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_address[0], fmt % args))


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    servers = [S(("0.0.0.0", p), H) for p in (8080, 8443)]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("sink listening on 8080 and 8443; Ctrl+C to stop")
    servers[0].serve_forever()
