"""SOC Agent step 4: phone web app.

A small web front end for the triage agent, so it can be used from a
phone: paste an incident or finding as JSON, get the verdict back.
Mobile-friendly page, installable on a home screen (PWA manifest +
generated icons).

Standard library only. No sign-in, no data saved, no keys: the mock
model runs offline, and the optional local Ollama model talks only to
localhost. The agent is still read-only -- the page can only ask for
verdicts, never act.

Run it:

    python3 app/server.py               # http://127.0.0.1:8081
    python3 app/server.py --port 8081   # same, explicit
"""

import argparse
import json
import os
import struct
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_agent
import evals as evals_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

DEFAULT_PORT = 8081


# ---------------------------------------------------------------------------
# Icons: a white blocky "S" on a dark rounded square, drawn in pure Python
# (same approach as the Ai Room icon: raw RGBA pixels, zlib, PNG chunks).
# ---------------------------------------------------------------------------

def _png_chunk(chunk_type, data):
    chunk = struct.pack(">I", len(data)) + chunk_type + data
    chunk += struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return chunk


def make_icon_png(size):
    """Return PNG bytes for a size x size icon."""
    bg = (11, 18, 32, 255)      # dark navy
    fg = (255, 255, 255, 255)   # white S
    radius = int(size * 0.18)
    # The S, as five bars in fractions of the canvas.
    bars = [
        (0.24, 0.20, 0.76, 0.32),  # top bar
        (0.24, 0.32, 0.38, 0.50),  # upper-left stem
        (0.24, 0.44, 0.76, 0.56),  # middle bar
        (0.62, 0.56, 0.76, 0.68),  # lower-right stem
        (0.24, 0.68, 0.76, 0.80),  # bottom bar
    ]

    def in_rounded_square(x, y):
        if x < radius and y < radius:
            return (x - radius) ** 2 + (y - radius) ** 2 <= radius ** 2
        if x >= size - radius and y < radius:
            return (x - (size - radius - 1)) ** 2 + (y - radius) ** 2 <= radius ** 2
        if x < radius and y >= size - radius:
            return (x - radius) ** 2 + (y - (size - radius - 1)) ** 2 <= radius ** 2
        if x >= size - radius and y >= size - radius:
            return (x - (size - radius - 1)) ** 2 + \
                (y - (size - radius - 1)) ** 2 <= radius ** 2
        return True

    raw = bytearray()
    for y in range(size):
        raw.append(0)  # no filter
        for x in range(size):
            fx, fy = x / size, y / size
            if not in_rounded_square(x, y):
                raw.extend((0, 0, 0, 0))
            elif any(x0 <= fx < x1 and y0 <= fy < y1
                     for (x0, y0, x1, y1) in bars):
                raw.extend(fg)
            else:
                raw.extend(bg)
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", header)
    png += _png_chunk(b"IDAT", zlib.compress(bytes(raw)))
    png += _png_chunk(b"IEND", b"")
    return png


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

def triage_item(item, model):
    """Triage one item dict with the chosen model, return the verdict."""
    if model == "ollama":
        client = soc_agent.OllamaClient()
    else:
        client = soc_agent.MockClient()
    verdict = soc_agent.triage(item, client)
    return {key: verdict[key] for key in (
        "verdict", "severity", "cause", "actions", "confidence",
        "item", "guidance_mitre",
    )}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            self.send_error(404, "not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send_file(os.path.join(STATIC_DIR, "index.html"),
                            "text/html; charset=utf-8")
        elif self.path == "/manifest.json":
            self._send_file(os.path.join(STATIC_DIR, "manifest.json"),
                            "application/manifest+json")
        elif self.path == "/icon-192.png":
            body = make_icon_png(192)
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/icon-512.png":
            body = make_icon_png(512)
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/health":
            self._send_json(200, {"ok": True})
        elif self.path == "/api/evals":
            results, passed, total = evals_mod.run_evals(
                evals_mod.load_cases(evals_mod.DEFAULT_CASES),
                soc_agent.MockClient(),
            )
            self._send_json(200, {
                "passed": passed,
                "total": total,
                "percent": (100 * passed // total) if total else 0,
                "results": results,
            })
        else:
            self.send_error(404, "not found")

    def do_POST(self):
        if self.path != "/api/triage":
            self.send_error(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "request body is not valid JSON"})
            return
        if not isinstance(payload, dict) or not isinstance(
                payload.get("item"), dict):
            self._send_json(400, {
                "error": "send JSON like {\"item\": {\"type\": \"brute_force\", ...}}"
            })
            return
        model = payload.get("model", "mock")
        if model not in ("mock", "ollama"):
            self._send_json(400, {
                "error": "model must be 'mock' or 'ollama'"
            })
            return
        try:
            verdict = triage_item(payload["item"], model)
        except RuntimeError as exc:
            self._send_json(502, {"error": str(exc)})
            return
        self._send_json(200, verdict)


def create_server(port=DEFAULT_PORT, host="127.0.0.1"):
    return ThreadingHTTPServer((host, port), Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description="SOC Agent step 4: web app.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="port to listen on (default: 8081)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="host to bind (default: 127.0.0.1)")
    args = parser.parse_args(argv)
    server = create_server(args.port, args.host)
    print("SOC Agent web app on http://{host}:{port}".format(
        host=args.host, port=args.port))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
