"""DeepTeam adapter for the local SecMate integration demo.

DeepTeam remains an optional dependency.  Imports are intentionally lazy so
the existing SecMate workflows continue to run when DeepTeam is not installed.
No credential values are accepted from API payloads or returned to callers.
"""

from __future__ import annotations

import asyncio
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from time import perf_counter
from typing import Any, Callable
from urllib.parse import urlparse


DEFAULT_VULNERABILITIES = ("PromptLeakage", "PIILeakage")
DEFAULT_ATTACKS = ("PromptInjection", "Roleplay")
MAX_TARGET_RESPONSE_BYTES = 1024 * 1024
ALLOWED_VULNERABILITIES = {
    "PromptLeakage",
    "PIILeakage",
    "SQLInjection",
    "ExcessiveAgency",
    "BOLA",
    "BFLA",
    "RBAC",
    "SSRF",
    "DebugAccess",
    "Hallucination",
}
ALLOWED_ATTACKS = {
    "PromptInjection",
    "Roleplay",
    "Base64",
    "ROT13",
    "Leetspeak",
    "PromptProbing",
    "SystemOverride",
}


class DeepTeamIntegrationError(Exception):
    """Raised when a requested DeepTeam scan cannot run safely."""


@dataclass(frozen=True)
class DeepTeamConfig:
    target_mode: str = "secmate_demo"
    target_endpoint: str | None = None
    vulnerabilities: tuple[str, ...] = DEFAULT_VULNERABILITIES
    attacks: tuple[str, ...] = DEFAULT_ATTACKS
    attacks_per_vulnerability_type: int = 1
    simulator_model: str = "gpt-4o-mini"
    evaluation_model: str = "gpt-4o-mini"

    @classmethod
    def from_payload(cls, payload: dict | None) -> "DeepTeamConfig":
        raw = payload or {}
        if not isinstance(raw, dict):
            raise ValueError("deepteam configuration must be a JSON object.")

        target_mode = str(raw.get("target_mode", "secmate_demo")).strip()
        if target_mode not in {"secmate_demo", "http"}:
            raise ValueError("DeepTeam target_mode must be 'secmate_demo' or 'http'.")

        target_endpoint = str(raw.get("target_endpoint", "") or "").strip() or None
        if len(target_endpoint or "") > 2048:
            raise ValueError("DeepTeam target_endpoint must be 2,048 characters or fewer.")
        if target_endpoint:
            validate_target_endpoint(target_endpoint, resolve_dns=False)
        if target_mode != "http" and target_endpoint:
            raise ValueError("DeepTeam target_endpoint is only valid when target_mode is 'http'.")

        vulnerabilities = _validated_names(
            raw.get("vulnerabilities", DEFAULT_VULNERABILITIES),
            ALLOWED_VULNERABILITIES,
            "vulnerabilities",
        )
        attacks = _validated_names(
            raw.get("attacks", DEFAULT_ATTACKS),
            ALLOWED_ATTACKS,
            "attacks",
        )
        try:
            attacks_per_type = int(raw.get("attacks_per_vulnerability_type", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("attacks_per_vulnerability_type must be an integer.") from exc
        if not 1 <= attacks_per_type <= 3:
            raise ValueError("attacks_per_vulnerability_type must be between 1 and 3.")

        simulator_model = str(raw.get("simulator_model", "gpt-4o-mini")).strip()
        evaluation_model = str(raw.get("evaluation_model", "gpt-4o-mini")).strip()
        if not simulator_model or not evaluation_model:
            raise ValueError("DeepTeam simulator and evaluation models are required.")

        return cls(
            target_mode=target_mode,
            target_endpoint=target_endpoint,
            vulnerabilities=vulnerabilities,
            attacks=attacks,
            attacks_per_vulnerability_type=attacks_per_type,
            simulator_model=simulator_model,
            evaluation_model=evaluation_model,
        )


def _validated_names(value: Any, allowed: set[str], label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"DeepTeam {label} must be a non-empty list.")
    names = tuple(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    unknown = sorted(set(names) - allowed)
    if unknown:
        raise ValueError(f"Unsupported DeepTeam {label}: {', '.join(unknown)}")
    return names


def _vendor_root() -> Path:
    project_root = Path(__file__).resolve().parents[1]
    candidates = (
        project_root / "vendor" / "deepteam",
        project_root.parent / "vendor" / "deepteam",
    )
    return next((candidate for candidate in candidates if candidate.is_dir()), candidates[0])


def _add_vendor_path() -> Path:
    vendor = _vendor_root()
    if vendor.is_dir() and str(vendor) not in sys.path:
        sys.path.insert(0, str(vendor))
    return vendor


def integration_status() -> dict:
    """Return readiness information without importing DeepTeam or exposing secrets."""
    vendor = _vendor_root()
    version_file = vendor / "deepteam" / "_version.py"
    version = None
    if version_file.is_file():
        match = re.search(
            r"__version__(?:\s*:\s*[^=]+)?\s*=\s*['\"]([^'\"]+)",
            version_file.read_text(encoding="utf-8"),
        )
        version = match.group(1) if match else None
    if version is None:
        try:
            version = package_version("deepteam")
        except PackageNotFoundError:
            version = None
    installed = importlib.util.find_spec("deepteam") is not None
    dependencies_ready, dependency_error = _deepteam_import_state()
    return {
        "source_available": vendor.is_dir() or installed,
        "source_mode": "vendored" if vendor.is_dir() else "installed_package" if installed else "unavailable",
        "deepteam_version": version,
        "dependencies_ready": dependencies_ready,
        "dependency_error": dependency_error,
        "openai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "http_target_configured": bool(
            os.getenv("DEEPTEAM_TARGET_URL") or os.getenv("DEEPTEAM_ALLOWED_TARGET_HOSTS")
        ),
        "target_modes": ["secmate_demo", "http"],
        "supported_vulnerabilities": sorted(ALLOWED_VULNERABILITIES),
        "supported_attacks": sorted(ALLOWED_ATTACKS),
        "note": "DeepTeam execution uses real generated/evaluated cases and requires its dependencies plus an evaluator model credential.",
    }


def _deepteam_import_state() -> tuple[bool, str | None]:
    """Return a public-safe readiness result without leaking paths or secrets."""
    _add_vendor_path()
    try:
        import deepteam  # noqa: F401
    except ModuleNotFoundError as exc:
        return False, f"Missing Python module: {exc.name}"
    except Exception as exc:
        return False, f"DeepTeam import failed ({type(exc).__name__})."
    return True, None


def _load_deepteam_components():
    vendor = _add_vendor_path()
    try:
        from deepteam import __version__, red_team
        from deepteam import vulnerabilities as vulnerability_module
        from deepteam.attacks import single_turn as attack_module
    except Exception as exc:
        source_hint = (
            "The vendored DeepTeam source was found, but its dependencies are unavailable."
            if vendor.is_dir()
            else "The DeepTeam package or one of its dependencies is unavailable."
        )
        raise DeepTeamIntegrationError(
            f"{source_hint} Install the production dependencies or run: "
            "pip install -r requirements-integration.txt"
        ) from exc
    return __version__, red_team, vulnerability_module, attack_module


def _allowed_target_hosts() -> set[str]:
    hosts = {
        item.strip().lower().rstrip(".")
        for item in os.getenv("DEEPTEAM_ALLOWED_TARGET_HOSTS", "").split(",")
        if item.strip()
    }
    configured_url = str(os.getenv("DEEPTEAM_TARGET_URL", "")).strip()
    if configured_url:
        configured_host = urlparse(configured_url).hostname
        if configured_host:
            hosts.add(configured_host.lower().rstrip("."))
    return hosts


def validate_target_endpoint(target_url: str, *, resolve_dns: bool = True) -> tuple:
    """Validate an analyst-supplied endpoint and return its parsed URL and public addresses."""
    parsed = urlparse(str(target_url).strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("DeepTeam target_endpoint must be an absolute HTTPS URL.")
    if parsed.username or parsed.password:
        raise ValueError("DeepTeam target_endpoint must not contain embedded credentials.")
    if parsed.fragment:
        raise ValueError("DeepTeam target_endpoint must not contain a URL fragment.")

    hostname = parsed.hostname.lower().rstrip(".")
    allowed_hosts = _allowed_target_hosts()
    if not allowed_hosts:
        raise ValueError(
            "HTTP target mode is disabled until DEEPTEAM_ALLOWED_TARGET_HOSTS or "
            "DEEPTEAM_TARGET_URL is configured by an administrator."
        )
    if hostname not in allowed_hosts:
        raise ValueError(
            f"Target hostname '{hostname}' is not in DEEPTEAM_ALLOWED_TARGET_HOSTS."
        )

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("DeepTeam target_endpoint contains an invalid port.") from exc

    addresses: tuple[str, ...] = ()
    if resolve_dns:
        try:
            resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DeepTeamIntegrationError(
                "The approved target hostname could not be resolved."
            ) from exc
        addresses = tuple(dict.fromkeys(item[4][0] for item in resolved))
        if not addresses:
            raise DeepTeamIntegrationError("The approved target hostname resolved to no addresses.")
        for address in addresses:
            try:
                is_public = ipaddress.ip_address(address).is_global
            except ValueError as exc:
                raise DeepTeamIntegrationError("The target resolved to an invalid address.") from exc
            if not is_public:
                raise DeepTeamIntegrationError(
                    "The target hostname resolves to a private, local, link-local, or reserved address."
                )
    return parsed, addresses


def build_model_callback(target_mode: str, target_endpoint: str | None = None) -> Callable:
    if target_mode == "secmate_demo":
        from blue_team.response_evaluator import simulate_target_response

        async def secmate_demo_callback(input: str) -> str:
            return simulate_target_response(input)

        return secmate_demo_callback

    target_url = str(target_endpoint or os.getenv("DEEPTEAM_TARGET_URL", "")).strip()
    if not target_url:
        raise DeepTeamIntegrationError(
            "A target_endpoint or DEEPTEAM_TARGET_URL is required when target_mode is 'http'."
        )
    try:
        parsed, resolved_addresses = validate_target_endpoint(target_url)
    except ValueError as exc:
        raise DeepTeamIntegrationError(str(exc)) from exc

    input_field = os.getenv("DEEPTEAM_TARGET_INPUT_FIELD", "input")
    output_field = os.getenv("DEEPTEAM_TARGET_OUTPUT_FIELD", "output")
    bearer_token = os.getenv("DEEPTEAM_TARGET_BEARER_TOKEN", "")
    timeout = min(max(float(os.getenv("DEEPTEAM_TARGET_TIMEOUT_SECONDS", "30")), 1), 120)

    def invoke_target(prompt: str) -> str:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        request_path = parsed.path or "/"
        if parsed.query:
            request_path = f"{request_path}?{parsed.query}"
        port = parsed.port or 443
        tls_context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            port,
            timeout=timeout,
            context=tls_context,
        )
        try:
            # Connect to an address validated above while preserving TLS SNI and
            # certificate verification for the approved hostname. This prevents
            # a second DNS lookup from redirecting the request to a private host.
            raw_socket = socket.create_connection((resolved_addresses[0], port), timeout=timeout)
            connection.sock = tls_context.wrap_socket(
                raw_socket,
                server_hostname=parsed.hostname,
            )
            connection.request(
                "POST",
                request_path,
                body=json.dumps({input_field: prompt}).encode("utf-8"),
                headers=headers,
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise DeepTeamIntegrationError("Target redirects are not allowed.")
            if response.status >= 400:
                raise DeepTeamIntegrationError(
                    f"The target returned HTTP {response.status}."
                )
            content_type = response.getheader("Content-Type", "")
            raw_body = response.read(MAX_TARGET_RESPONSE_BYTES + 1)
        finally:
            connection.close()
        if len(raw_body) > MAX_TARGET_RESPONSE_BYTES:
            raise DeepTeamIntegrationError("The target response exceeded the 1 MB safety limit.")
        body = raw_body.decode("utf-8")
        if "application/json" in content_type:
            parsed_body = json.loads(body)
            output = parsed_body.get(output_field) if isinstance(parsed_body, dict) else None
        else:
            output = body
        if not isinstance(output, str) or not output.strip():
            raise DeepTeamIntegrationError(
                f"The target response did not contain a non-empty '{output_field}' string."
            )
        return output

    async def http_callback(input: str) -> str:
        return await asyncio.to_thread(invoke_target, input)

    return http_callback


def run_deepteam_scan(target: str, config: DeepTeamConfig) -> dict:
    """Execute DeepTeam and return normalized SecMate-compatible data."""
    if not os.getenv("OPENAI_API_KEY"):
        raise DeepTeamIntegrationError(
            "OPENAI_API_KEY is required by this demo's DeepTeam simulator/evaluator models."
        )

    version, red_team, vulnerability_module, attack_module = _load_deepteam_components()
    vulnerabilities = [
        getattr(vulnerability_module, name)(
            async_mode=True,
            simulator_model=config.simulator_model,
            evaluation_model=config.evaluation_model,
        )
        for name in config.vulnerabilities
    ]
    attacks = [getattr(attack_module, name)() for name in config.attacks]
    callback = build_model_callback(config.target_mode, config.target_endpoint)

    started = perf_counter()
    try:
        assessment = red_team(
            model_callback=callback,
            vulnerabilities=vulnerabilities,
            attacks=attacks,
            simulator_model=config.simulator_model,
            evaluation_model=config.evaluation_model,
            attacks_per_vulnerability_type=config.attacks_per_vulnerability_type,
            async_mode=True,
            target_purpose=f"Security assessment of {target}",
            identifier=f"secmate:{target}",
        )
    except Exception as exc:
        raise DeepTeamIntegrationError(f"DeepTeam assessment failed: {exc}") from exc

    normalized = normalize_risk_assessment(assessment, target=target)
    normalized["metadata"].update(
        {
            "deepteam_version": version,
            "target_mode": config.target_mode,
            "target_endpoint_host": (
                urlparse(config.target_endpoint or os.getenv("DEEPTEAM_TARGET_URL", "")).hostname
                if config.target_mode == "http"
                else None
            ),
            "simulator_model": config.simulator_model,
            "evaluation_model": config.evaluation_model,
            "configured_vulnerabilities": list(config.vulnerabilities),
            "configured_attacks": list(config.attacks),
            "adapter_duration_ms": round((perf_counter() - started) * 1000, 2),
            "target_is_simulated": config.target_mode == "secmate_demo",
        }
    )
    return normalized


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "Unknown")


def _numeric_score(value: Any) -> float | None:
    """Return a numeric DeepTeam score without trusting external object types."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _transcript_output(case: Any) -> str:
    direct = _get(case, "actual_output")
    if direct:
        return str(direct)
    turns = _get(case, "turns", []) or []
    assistant_turns = [
        str(_get(turn, "content", ""))
        for turn in turns
        if str(_get(turn, "role", "")).lower() in {"assistant", "target"}
    ]
    return assistant_turns[-1] if assistant_turns else ""


def _severity_from_cvss(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "Info"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def normalize_risk_assessment(assessment: Any, target: str) -> dict:
    """Map a DeepTeam RiskAssessment into SecMate test cases and findings."""
    normalized_cases = []
    findings = []
    for index, case in enumerate(_get(assessment, "test_cases", []) or [], start=1):
        case_id = f"DT-{index:03d}"
        score = _get(case, "score")
        numeric_score = _numeric_score(score)
        error = _get(case, "error")
        if error:
            verdict = "Requires Review"
        elif numeric_score is None:
            verdict = "Requires Review"
        elif numeric_score > 0:
            verdict = "Defended"
        else:
            verdict = "Potential Bypass"

        vulnerability = str(_get(case, "vulnerability", "DeepTeam"))
        vulnerability_type = _enum_value(_get(case, "vulnerability_type"))
        attack_method = _enum_value(_get(case, "attack_method", "Baseline"))
        reason = str(_get(case, "reason") or error or "DeepTeam returned no evaluation reason.")
        output = _transcript_output(case)
        cvss_score = _get(case, "cvss_score")
        risk_category = str(_get(case, "risk_category", "AI Security") or "AI Security")

        normalized_case = {
            "id": case_id,
            "category": f"DeepTeam / {vulnerability}",
            "target": target,
            "prompt": str(_get(case, "input", "") or ""),
            "simulated_response": output,
            "verdict": verdict,
            "explanation": reason,
            "matched_markers": {
                "deepteam_score": numeric_score,
                "vulnerability_type": vulnerability_type,
                "attack_method": attack_method,
                "risk_category": risk_category,
                "cvss_score": cvss_score,
            },
            "source_engine": "DeepTeam",
        }
        normalized_cases.append(normalized_case)

        if verdict == "Potential Bypass":
            slug = re.sub(r"[^A-Z0-9]+", "-", vulnerability_type.upper()).strip("-")
            findings.append(
                {
                    "rule_id": f"DEEPTEAM-{slug or index}",
                    "title": f"DeepTeam finding — {vulnerability_type}",
                    "severity": _severity_from_cvss(cvss_score),
                    "description": reason,
                    "evidence": output[:500] or str(_get(case, "input", ""))[:500],
                    "recommendation": (
                        f"Review the DeepTeam {vulnerability_type} transcript and strengthen controls "
                        "for this behavior before re-running the assessment."
                    ),
                    "related_assessment_id": None,
                    "target": target,
                    "status": "DeepTeam Evaluated Finding",
                    "matched_text": vulnerability_type,
                    "provenance": {
                        "source_type": "deepteam_test_case",
                        "source_ref": case_id,
                        "target": target,
                    },
                    "confidence": {
                        "level": "High",
                        "basis": "DeepTeam evaluated the target response and returned a failing score.",
                    },
                    "deepteam": {
                        "score": numeric_score,
                        "cvss_score": cvss_score,
                        "attack_method": attack_method,
                        "risk_category": risk_category,
                    },
                }
            )

    overview = _get(assessment, "overview")
    metadata = {
        "test_case_count": len(normalized_cases),
        "finding_count": len(findings),
        "run_duration_seconds": _get(overview, "run_duration"),
        "cvss_score": _get(overview, "cvss_score"),
    }
    return {"test_cases": normalized_cases, "findings": findings, "metadata": metadata}
