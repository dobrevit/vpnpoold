#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time


OBSERVED_IPS = {
    "10.250.0.10": "198.51.100.10",
    "10.250.0.11": "198.51.100.11",
    "10.250.0.12": "198.51.100.12",
    "10.250.0.13": "198.51.100.13",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.partition("?")[0]
        if path not in ("/ip", "/hold"):
            self.send_error(404)
            return
        observed = OBSERVED_IPS.get(self.client_address[0])
        if observed is None:
            self.send_error(403)
            return
        body = f"{observed}\n".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if path == "/ip":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if path == "/hold":
            time.sleep(60)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("10.250.0.1", 8080), Handler).serve_forever()
