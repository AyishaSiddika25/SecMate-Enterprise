import json
import sys
import os
from http.server import BaseHTTPRequestHandler

# Add repository root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from core import engine
except Exception as e:
    engine = None
    IMPORT_ERROR = str(e)


class handler(BaseHTTPRequestHandler):

    def send_json(self, status_code, data):
        body = json.dumps(data, default=str).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_json(200, {"ok": True})

    def do_GET(self):
        if engine is None:
            self.send_json(
                500,
                {
                    "application": "SecMate Enterprise",
                    "status": "error",
                    "message": "Engine import failed",
                    "error": IMPORT_ERROR,
                },
            )
            return

        self.send_json(
            200,
            {
                "application": "SecMate Enterprise",
                "status": "online",
                "mode": "API",
                "engine": "loaded",
                "message": "SecMate API is running",
            },
        )

    def do_POST(self):
        if engine is None:
            self.send_json(
                500,
                {
                    "ok": False,
                    "error": "Engine import failed",
                    "details": IMPORT_ERROR,
                },
            )
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            data = json.loads(body.decode("utf-8"))

            target = str(data.get("target", "")).strip()
            workflow = str(data.get("workflow", "")).strip()
            intensity = str(data.get("intensity", "Standard")).strip()
            evidence = str(data.get("evidence", "") or "")

            if not target:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Target is required",
                    },
                )
                return

            if not workflow:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": "Workflow is required",
                        "available_workflows": engine.ALL_WORKFLOWS,
                    },
                )
                return

            if workflow not in engine.ALL_WORKFLOWS:
                self.send_json(
                    400,
                    {
                        "ok": False,
                        "error": f"Unknown workflow: {workflow}",
                        "available_workflows": engine.ALL_WORKFLOWS,
                    },
                )
                return

            record = engine.run_assessment(
                target=target,
                workflow=workflow,
                intensity=intensity,
                evidence=evidence,
            )

            self.send_json(
                200,
                {
                    "ok": True,
                    "application": "SecMate Enterprise",
                    "assessment": record,
                },
            )

        except json.JSONDecodeError:
            self.send_json(
                400,
                {
                    "ok": False,
                    "error": "Invalid JSON request body",
                },
            )

        except Exception as e:
            self.send_json(
                500,
                {
                    "ok": False,
                    "error": "Assessment execution failed",
                    "details": str(e),
                },
            )
