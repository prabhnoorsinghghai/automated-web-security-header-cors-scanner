"""
Practice servers for testing the scanner safely on your own computer.
Run this in one window:   python test_servers.py
Then in a second window:  python PrabhnoorSinghGhai_WebSecurityScanner.py http://127.0.0.1:8081 http://127.0.0.1:8082
Port 8081 = deliberately WEAK site (expect a very low score).
Port 8082 = well-protected site (expect a very high score).
Press Ctrl+C to stop.
"""
import http.server
import threading
import time


class WeakSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Set-Cookie", "session=abc123")
        self.end_headers()
        self.wfile.write(b"weak site")

    def log_message(self, *args):
        pass


class StrongSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        for name, value in [
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "camera=()"),
            ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Strict"),
        ]:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(b"strong site")

    def log_message(self, *args):
        pass


for port, handler in [(8081, WeakSite), (8082, StrongSite)]:
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
print("Test servers running on ports 8081 (weak) and 8082 (strong). Press Ctrl+C to stop.")
while True:
    time.sleep(1)
