import os, time, signal, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MARKER = "/tmp/fleetwide-restarted"
START = time.time()
FIRST_RUN = not os.path.exists(MARKER)
open(MARKER, "w").write(str(os.getpid()))

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            sick = FIRST_RUN and time.time() - START > 6
            self.send_response(500 if sick else 200)
            self.end_headers()
            self.wfile.write(b"sick\n" if sick else b"ok\n")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(("flaky pid=%d first_run=%s\n" % (os.getpid(), FIRST_RUN)).encode())
    def log_message(self, *a):  # quiet
        pass

def term(*_):
    print("flaky: SIGTERM, exiting", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, term)
print("flaky: start pid=%d first_run=%s" % (os.getpid(), FIRST_RUN), flush=True)
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
