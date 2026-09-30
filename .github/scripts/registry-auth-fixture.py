"""Loopback-only Docker login fixture; no image storage or registry writes."""

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer


class RegistryAuth(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/v2/":
            self.send_error(404)
            return

        # Public test strings, never repository credentials or real secrets.
        expected = "Basic " + base64.b64encode(b"ci-smoke:not-a-secret").decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="action-smoke"')
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
        self.end_headers()
        self.wfile.write(b"{}")


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 5000), RegistryAuth).serve_forever()
