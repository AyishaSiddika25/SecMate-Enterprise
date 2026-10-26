"""Vercel serverless entrypoint for SecMate assessments."""

import json
import logging
import uuid
from http.server import BaseHTTPRequestHandler

from core.intelligence import compare_assessments
from core.engine import EngineError, run_assessment
from integrations.combined_engine import run_combined_assessment
from integrations.deepteam_adapter import DeepTeamIntegrationError, integration_status


MAX_BODY_BYTES = 1024 * 1024
LOGGER = logging.getLogger("secmate.api")


def process_assessment(payload: dict) -> dict:
    """Validate an API payload and run the existing assessment engine."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")

    target = str(payload.get("target", "")).strip()
    workflow = str(payload.get("workflow", "")).strip()
    intensity = str(payload.get("intensity", "Standard")).strip()
    evidence = str(payload.get("evidence", ""))

    if not target:
        raise ValueError("Target is required.")
    if len(target) > 200:
        raise ValueError("Target must be 200 characters or fewer.")
    if len(evidence) > 50_000:
        raise ValueError("Evidence must be 50,000 characters or fewer.")

    return {"ok": True, **run_assessment(target, workflow, intensity, evidence)}


def process_request(payload: dict) -> dict:
    """Dispatch existing SecMate actions plus the opt-in DeepTeam demo."""
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    action = str(payload.get("action", "assess")).strip().lower()
    if action == "assess":
        return process_assessment(payload)
    if action == "compare":
        comparison = compare_assessments(payload.get("baseline"), payload.get("candidate"))
        return {"ok": True, "action": "compare", "comparison": comparison}
    if action == "deepteam_status":
        return {"ok": True, "action": "deepteam_status", "deepteam": integration_status()}
    if action == "deepteam_assess":
        target = str(payload.get("target", "")).strip()
        intensity = str(payload.get("intensity", "Standard")).strip()
        evidence = str(payload.get("evidence", ""))
        if not target:
            raise ValueError("Target is required.")
        if len(target) > 200:
            raise ValueError("Target must be 200 characters or fewer.")
        if len(evidence) > 50_000:
            raise ValueError("Evidence must be 50,000 characters or fewer.")
        return {
            "ok": True,
            **run_combined_assessment(
                target=target,
                intensity=intensity,
                evidence=evidence,
                deepteam_config=payload.get("deepteam"),
            ),
        }
    raise ValueError(f"Unknown API action: {action}")


class handler(BaseHTTPRequestHandler):
    """HTTP handler discovered by Vercel's Python runtime."""

    def _send_json(self, status: int, payload: dict, request_id: str = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if request_id:
            self.send_header("X-Request-ID", request_id)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send_json(
            200,
            {
                "ok": True,
                "service": "SecMate Enterprise API",
                "status": "ok",
                "schema_version": 2,
                "actions": ["assess", "compare", "deepteam_status", "deepteam_assess"],
            },
        )

    def do_POST(self) -> None:
        request_id = uuid.uuid4().hex[:12]
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                raise ValueError("A JSON request body is required.")
            if content_length > MAX_BODY_BYTES:
                self._send_json(413, {"ok": False, "error": "Request body is too large.", "code": "body_too_large"}, request_id)
                return

            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8"))
            result = process_request(payload)
            self._send_json(200, result, request_id)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "Request body must contain valid JSON.", "code": "invalid_json"}, request_id)
        except (ValueError, EngineError) as exc:
            self._send_json(400, {"ok": False, "error": str(exc), "code": "invalid_request"}, request_id)
        except DeepTeamIntegrationError as exc:
            self._send_json(
                503,
                {"ok": False, "error": str(exc), "code": "deepteam_unavailable"},
                request_id,
            )
        except Exception:
            LOGGER.exception("Unhandled SecMate API error; request_id=%s", request_id)
            self._send_json(
                500,
                {
                    "ok": False,
                    "error": "Assessment failed unexpectedly. Use the request ID when reviewing server logs.",
                    "code": "assessment_failed",
                    "request_id": request_id,
                },
                request_id,
            )

    def log_message(self, format: str, *args) -> None:
        """Keep Vercel function logs concise."""
        return
