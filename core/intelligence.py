"""Derived security intelligence built from SecMate assessment records.

The helpers in this module never scan a target or invent observations. They
normalize, correlate, compare, map, and package data already produced by the
existing Red Team, Blue Team, and VAPT modules.
"""

import hashlib
import json
import re
from copy import deepcopy


SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|password|token)\b\s*[:=]\s*"
    r"(['\"]?)([^\s,'\";]{4,})\2"
)


CATEGORY_MAPPINGS = {
    "Prompt Injection": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "The test explicitly attempts to override higher-priority model instructions.",
        }
    ],
    "Jailbreak / Roleplay": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "Roleplay and jailbreak framing is used to induce instruction-policy bypass.",
        }
    ],
    "Data Exfiltration": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM02:2025",
            "name": "Sensitive Information Disclosure",
            "rationale": "The test requests confidential instructions, credentials, or internal context.",
        },
        {
            "framework": "MITRE ATT&CK",
            "control_id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "rationale": "Applied only to a Potential Bypass outcome where an exfiltration-style request elicited disclosure-like output; this is behavioral context, not proof of network exfiltration.",
        },
    ],
    "Harmful Content Elicitation": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM05:2025",
            "name": "Improper Output Handling",
            "rationale": "The test evaluates whether unsafe generated output is returned without adequate handling.",
        }
    ],
    "Instruction Override": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "The prompt directly requests that system or developer instructions be ignored.",
        }
    ],
    "Context Manipulation": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "The test supplies false conversation context to alter instruction priority.",
        }
    ],
}


RULE_MAPPINGS = {
    "VAPT-CREDENTIAL-001": [
        {
            "framework": "MITRE ATT&CK",
            "control_id": "T1552.001",
            "name": "Unsecured Credentials: Credentials In Files",
            "rationale": "The matched evidence contains a credential-like value embedded in supplied text.",
        },
        {
            "framework": "CWE",
            "control_id": "CWE-798",
            "name": "Use of Hard-coded Credentials",
            "rationale": "The detector specifically matches hardcoded credential assignments.",
        },
    ],
    "VAPT-PROMPT-LEAK-002": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM07:2025",
            "name": "System Prompt Leakage",
            "rationale": "The supplied evidence contains language associated with disclosure of system-level instructions.",
        }
    ],
    "VAPT-PII-003": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM02:2025",
            "name": "Sensitive Information Disclosure",
            "rationale": "The evidence contains a deterministic pattern resembling PII.",
        }
    ],
    "VAPT-RATE-004": [
        {
            "framework": "OWASP API Security Top 10",
            "control_id": "API4:2023",
            "name": "Unrestricted Resource Consumption",
            "rationale": "The evidence explicitly indicates missing request throttling or rate limits.",
        }
    ],
    "VAPT-ERROR-005": [
        {
            "framework": "CWE",
            "control_id": "CWE-209",
            "name": "Generation of Error Message Containing Sensitive Information",
            "rationale": "The detector matches verbose errors or stack-trace disclosure.",
        },
        {
            "framework": "OWASP Web Top 10",
            "control_id": "A05:2021",
            "name": "Security Misconfiguration",
            "rationale": "Verbose production error output is a security-configuration weakness.",
        },
    ],
    "VAPT-JAILBREAK-006": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "The evidence contains output markers associated with jailbreak compliance.",
        }
    ],
    "VAPT-IDOR-007": [
        {
            "framework": "CWE",
            "control_id": "CWE-639",
            "name": "Authorization Bypass Through User-Controlled Key",
            "rationale": "The detector matches a directly addressable object identifier without nearby authorization context.",
        },
        {
            "framework": "OWASP Web Top 10",
            "control_id": "A01:2021",
            "name": "Broken Access Control",
            "rationale": "IDOR is an object-level access-control weakness.",
        },
    ],
    "VAPT-PRIVILEGE-008": [
        {
            "framework": "CWE",
            "control_id": "CWE-250",
            "name": "Execution with Unnecessary Privileges",
            "rationale": "The supplied evidence indicates broad administrative permissions.",
        }
    ],
    "BLUE-BYPASS": [
        {
            "framework": "OWASP LLM Top 10",
            "control_id": "LLM01:2025",
            "name": "Prompt Injection",
            "rationale": "A Blue Team evaluator observed compliance or disclosure markers after an adversarial prompt.",
        }
    ],
}


def _normalized(value) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def redact_sensitive_text(value: str) -> str:
    """Redact common credential assignments from export/replay text."""
    return SENSITIVE_VALUE_PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(value or ""))


def finding_fingerprint(finding: dict) -> str:
    """Return a stable identity for equivalent findings across assessment runs."""
    identity = "|".join(
        [
            _normalized(finding.get("rule_id") or finding.get("title")),
            _normalized(finding.get("target")),
            _normalized(finding.get("matched_text") or finding.get("title")),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def enrich_and_correlate_findings(findings: list) -> tuple[list, list]:
    """Add fingerprints and group repeated findings without losing occurrences."""
    enriched = []
    groups = {}
    for index, raw in enumerate(findings or []):
        finding = deepcopy(raw)
        fingerprint = finding.get("fingerprint") or finding_fingerprint(finding)
        finding["fingerprint"] = fingerprint
        finding.setdefault("finding_id", f"F-{fingerprint[:10].upper()}")
        enriched.append(finding)

        group = groups.setdefault(
            fingerprint,
            {
                "fingerprint": fingerprint,
                "finding_id": finding["finding_id"],
                "title": finding.get("title", "Security indicator"),
                "severity": finding.get("severity", "Info"),
                "target": finding.get("target"),
                "occurrence_count": 0,
                "occurrences": [],
                "recommendation": finding.get("recommendation", ""),
            },
        )
        group["occurrence_count"] += 1
        group["occurrences"].append(
            {
                "index": index,
                "assessment_id": finding.get("related_assessment_id"),
                "source": finding.get("provenance", {}),
                "evidence": finding.get("evidence", ""),
            }
        )

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    correlated = sorted(
        groups.values(),
        key=lambda group: (severity_rank.get(group.get("severity"), 5), group.get("title", "")),
    )
    return enriched, correlated


def build_outcome_matrix(test_cases: list) -> list:
    """Aggregate real Blue Team outcomes by Red Team attack category."""
    rows = {}
    for case in test_cases or []:
        category = case.get("category") or "Uncategorized"
        row = rows.setdefault(
            category,
            {
                "category": category,
                "total": 0,
                "defended": 0,
                "requires_review": 0,
                "potential_bypass": 0,
                "test_case_ids": [],
            },
        )
        row["total"] += 1
        row["test_case_ids"].append(case.get("id"))
        verdict = case.get("verdict")
        if verdict == "Defended":
            row["defended"] += 1
        elif verdict == "Potential Bypass":
            row["potential_bypass"] += 1
        else:
            row["requires_review"] += 1
    return list(rows.values())


def build_framework_mappings(test_cases: list, findings: list) -> list:
    """Return only mappings justified by an observed case or finding."""
    output = []
    seen = set()

    for case in test_cases or []:
        category = case.get("category")
        if case.get("verdict") == "Defended":
            continue
        for mapping in CATEGORY_MAPPINGS.get(category, []):
            if mapping["framework"] == "MITRE ATT&CK" and case.get("verdict") != "Potential Bypass":
                continue
            item = {
                **mapping,
                "source_type": "test_case",
                "source_ref": case.get("id"),
                "source_category": category,
            }
            key = (item["framework"], item["control_id"], item["source_ref"])
            if key not in seen:
                seen.add(key)
                output.append(item)

    for finding in findings or []:
        for mapping in RULE_MAPPINGS.get(finding.get("rule_id"), []):
            item = {
                **mapping,
                "source_type": "finding",
                "source_ref": finding.get("finding_id") or finding.get("fingerprint"),
                "source_category": finding.get("title"),
            }
            key = (item["framework"], item["control_id"], item["source_ref"])
            if key not in seen:
                seen.add(key)
                output.append(item)
    return output


def build_relationship_graph(target: str, test_cases: list, findings: list) -> dict:
    """Build an evidence-backed relationship graph, not a speculative exploit path."""
    target_id = "target"
    nodes = [{"id": target_id, "type": "target", "label": target}]
    edges = []
    test_node_ids = set()

    for case in test_cases or []:
        if case.get("verdict") == "Defended":
            continue
        case_id = f"test:{case.get('id')}"
        test_node_ids.add(case_id)
        nodes.append(
            {
                "id": case_id,
                "type": "test_case",
                "label": case.get("category", "Adversarial test"),
                "status": case.get("verdict"),
                "source_ref": case.get("id"),
            }
        )
        edges.append({"from": target_id, "to": case_id, "relationship": "tested by"})

    for finding in findings or []:
        finding_id = f"finding:{finding.get('finding_id') or finding.get('fingerprint')}"
        nodes.append(
            {
                "id": finding_id,
                "type": "finding",
                "label": finding.get("title", "Security indicator"),
                "status": finding.get("severity", "Info"),
                "source_ref": finding.get("finding_id") or finding.get("fingerprint"),
            }
        )
        source_ref = finding.get("provenance", {}).get("source_ref")
        source_node = f"test:{source_ref}"
        if source_node in test_node_ids:
            edges.append({"from": source_node, "to": finding_id, "relationship": "produced indicator"})
        else:
            edges.append({"from": target_id, "to": finding_id, "relationship": "evidence indicates"})

    return {
        "graph_type": "assessment_relationships",
        "disclaimer": "Edges represent observed assessment relationships, not confirmed exploitability.",
        "nodes": nodes,
        "edges": edges,
    }


def build_replay_manifest(record: dict, intensity_config: dict) -> dict:
    """Create a sanitized, deterministic replay/export package."""
    evidence = record.get("evidence_input", "")
    sanitized_findings = []
    for raw in record.get("vapt_findings", []):
        finding = deepcopy(raw)
        finding["evidence"] = redact_sensitive_text(finding.get("evidence", ""))
        if "matched_text" in finding:
            finding["matched_text"] = redact_sensitive_text(finding.get("matched_text", ""))
        sanitized_findings.append(finding)

    return {
        "manifest_version": 1,
        "assessment_id": record.get("assessment_id"),
        "engine_contract": "SecMate deterministic assessment record v2",
        "configuration": {
            "workflow": record.get("assessment_type"),
            "intensity": record.get("intensity"),
            "intensity_config": deepcopy(intensity_config),
        },
        "inputs": {
            "target": record.get("target"),
            "evidence_redacted": redact_sensitive_text(evidence),
            "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        },
        "outputs": {
            "overall_verdict": record.get("overall_verdict"),
            "posture": deepcopy(record.get("posture", {})),
            "test_cases": deepcopy(record.get("test_cases", [])),
            "vapt_findings": sanitized_findings,
        },
        "sensitive_values_redacted": True,
    }


def _finding_index(record: dict) -> dict:
    findings = record.get("vapt_findings", []) or []
    enriched, _ = enrich_and_correlate_findings(findings)
    return {finding["fingerprint"]: finding for finding in enriched}


def compare_assessments(baseline: dict, candidate: dict) -> dict:
    """Compare two completed real assessment records."""
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        raise ValueError("Baseline and candidate assessments must be JSON objects.")
    for label, record in (("Baseline", baseline), ("Candidate", candidate)):
        if not record.get("assessment_id"):
            raise ValueError(f"{label} assessment_id is required.")
        if record.get("status") not in (None, "Completed"):
            raise ValueError(f"{label} assessment must be completed before comparison.")

    base_findings = _finding_index(baseline)
    candidate_findings = _finding_index(candidate)
    base_ids = set(base_findings)
    candidate_ids = set(candidate_findings)

    def summarize(finding: dict) -> dict:
        return {
            "fingerprint": finding.get("fingerprint"),
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "target": finding.get("target"),
        }

    unchanged = []
    changed = []
    for fingerprint in sorted(base_ids & candidate_ids):
        before = base_findings[fingerprint]
        after = candidate_findings[fingerprint]
        item = {"before": summarize(before), "after": summarize(after)}
        if before.get("severity") == after.get("severity"):
            unchanged.append(item)
        else:
            changed.append(item)

    base_score = baseline.get("posture", {}).get("score")
    candidate_score = candidate.get("posture", {}).get("score")
    score_delta = None
    if isinstance(base_score, (int, float)) and isinstance(candidate_score, (int, float)):
        score_delta = round(candidate_score - base_score, 2)

    return {
        "baseline_assessment_id": baseline["assessment_id"],
        "candidate_assessment_id": candidate["assessment_id"],
        "same_target": baseline.get("target") == candidate.get("target"),
        "new_findings": [summarize(candidate_findings[item]) for item in sorted(candidate_ids - base_ids)],
        "resolved_findings": [summarize(base_findings[item]) for item in sorted(base_ids - candidate_ids)],
        "unchanged_findings": unchanged,
        "severity_changed_findings": changed,
        "verdict": {
            "before": baseline.get("overall_verdict"),
            "after": candidate.get("overall_verdict"),
            "changed": baseline.get("overall_verdict") != candidate.get("overall_verdict"),
        },
        "posture_score": {"before": base_score, "after": candidate_score, "delta": score_delta},
        "red_blue": {
            "defended_delta": candidate.get("defended_count", 0) - baseline.get("defended_count", 0),
            "review_delta": candidate.get("review_required_count", 0) - baseline.get("review_required_count", 0),
            "bypass_delta": sum(1 for case in candidate.get("test_cases", []) if case.get("verdict") == "Potential Bypass")
            - sum(1 for case in baseline.get("test_cases", []) if case.get("verdict") == "Potential Bypass"),
        },
    }


def intelligence_payload(record: dict) -> dict:
    """Return the optional intelligence fields persisted alongside legacy columns."""
    keys = (
        "schema_version",
        "posture",
        "outcome_matrix",
        "correlated_findings",
        "mappings",
        "relationship_graph",
        "replay",
        "progress",
        "notes",
    )
    return {key: deepcopy(record[key]) for key in keys if key in record}


def stable_json_hash(value) -> str:
    """Used by tests and future report integrity checks."""
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
