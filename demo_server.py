"""Local-only HTTP server for the SecMate + DeepTeam integration demo."""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from api.index import MAX_BODY_BYTES, process_request
from core.engine import EngineError
from integrations.deepteam_adapter import DeepTeamIntegrationError


ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("secmate.deepteam.demo")


class DemoHandler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api":
            self._json(200, process_request({"action": "deepteam_status"}))
            return
        if path not in {"/", "/index.html"}:
            self._json(404, {"ok": False, "error": "Not found."})
            return
        body = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api":
            self._json(404, {"ok": False, "error": "Not found."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                raise ValueError("A JSON request body is required.")
            if content_length > MAX_BODY_BYTES:
                self._json(413, {"ok": False, "error": "Request body is too large."})
                return
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            self._json(200, process_request(payload))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"ok": False, "error": "Request body must contain valid JSON."})
        except (ValueError, EngineError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        except DeepTeamIntegrationError as exc:
            self._json(503, {"ok": False, "error": str(exc), "code": "deepteam_unavailable"})
        except Exception:
            LOGGER.exception("Unhandled local demo error")
            self._json(500, {"ok": False, "error": "The local integration demo failed unexpectedly."})

    def log_message(self, format: str, *args) -> None:
        LOGGER.info(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SecMate + DeepTeam demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4175)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"SecMate + DeepTeam demo: http://{args.host}:{args.port}")
    print("Local demo only. No Vercel deployment is configured or performed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
