"""A deliberately-vulnerable benchmark web target for the ASAA demo.

Stands in for DVWA / Juice Shop / Metasploitable when those containers are not
available. It advertises an intentionally outdated stack (old Apache, PHP,
WordPress, jQuery, Bootstrap) and omits every security header, so Mode 1 does
GENUINE fingerprinting and the CVE matcher finds real CVEs. Not a mock of the
scanner — a real target for the real scanner.

Run:  python scripts/mock_target.py 8000
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HTML = """<!doctype html><html><head>
<meta name="generator" content="WordPress 4.6.1">
<link rel="stylesheet" href="/assets/bootstrap-3.3.7.min.css">
</head><body>
<h1>Al-Waha Portal (benchmark)</h1>
<p>Intentionally vulnerable target for ASAA assessment.</p>
<script src="/assets/jquery-1.12.4.min.js"></script>
<script src="/assets/bootstrap-3.3.7.min.js"></script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = ""

    def _send(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("X-Powered-By", "PHP/7.2.1")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        # deliberately no CSP / HSTS / X-Frame-Options / etc.
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send()

    def do_HEAD(self):
        self._send()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"Benchmark target on http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
