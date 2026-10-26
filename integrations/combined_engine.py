"""Composition layer that combines SecMate and DeepTeam assessment results."""

from __future__ import annotations

from time import perf_counter

from core import intelligence
from core.engine import INTENSITY_CONFIG, WORKFLOW_COMBINED, EngineError, run_assessment
from integrations.deepteam_adapter import DeepTeamConfig, run_deepteam_scan
from vapt import security_decision, validate_llm_output


def run_combined_assessment(
    target: str,
    intensity: str,
    evidence: str = "",
    deepteam_config: dict | None = None,
) -> dict:
    """Run SecMate first, then merge a real DeepTeam risk assessment.

    The existing SecMate engine is called without modification.  DeepTeam data
    is normalized into the established SecMate test-case/finding contracts and
    all derived intelligence is recalculated from the merged evidence.
    """
    config = DeepTeamConfig.from_payload(deepteam_config)
    record = run_assessment(target, WORKFLOW_COMBINED, intensity, evidence)
    record["progress"] = [
        event for event in record.get("progress", []) if event.get("stage") != "record_validation"
    ]

    started = perf_counter()
    deepteam_result = run_deepteam_scan(target, config)
    duration_ms = round((perf_counter() - started) * 1000, 2)
    for finding in deepteam_result["findings"]:
        finding["related_assessment_id"] = record["assessment_id"]
        finding["provenance"]["assessment_id"] = record["assessment_id"]

    record["test_cases"] = list(record.get("test_cases", [])) + deepteam_result["test_cases"]
    merged_findings = list(record.get("vapt_findings", [])) + deepteam_result["findings"]
    record["vapt_findings"], record["correlated_findings"] = intelligence.enrich_and_correlate_findings(
        merged_findings
    )

    canonical_findings = []
    by_fingerprint = {
        finding["fingerprint"]: finding for finding in record["vapt_findings"]
    }
    for group in record["correlated_findings"]:
        canonical = by_fingerprint.get(group["fingerprint"])
        if canonical:
            canonical_findings.append(canonical)

    record["overall_verdict"] = security_decision.compute_overall_verdict(
        record["test_cases"], canonical_findings
    )
    summary = security_decision.summarize_test_cases(record["test_cases"])
    record["test_case_count"] = summary["total"]
    record["defended_count"] = summary["defended"]
    record["review_required_count"] = summary["requires_review"]
    record["vapt_indicator_count"] = len(record["vapt_findings"])
    record["posture"] = security_decision.compute_posture_score(
        record["test_cases"], canonical_findings, record["overall_verdict"]
    )
    record["outcome_matrix"] = intelligence.build_outcome_matrix(record["test_cases"])
    record["mappings"] = intelligence.build_framework_mappings(
        record["test_cases"], record["vapt_findings"]
    ) + _deepteam_taxonomy_mappings(deepteam_result["test_cases"])
    record["relationship_graph"] = intelligence.build_relationship_graph(
        target, record["test_cases"], record["vapt_findings"]
    )

    record["deepteam"] = {
        "enabled": True,
        **deepteam_result["metadata"],
    }
    if config.target_mode == "secmate_demo":
        record.setdefault("notes", []).append(
            "DeepTeam evaluated SecMate's deterministic demo target callback; this is not a live production target result."
        )
    record["progress"].append(
        {
            "stage": "deepteam_red_teaming",
            "status": "Completed",
            "duration_ms": duration_ms,
            "detail": (
                f"DeepTeam evaluated {len(deepteam_result['test_cases'])} case(s) and produced "
                f"{len(deepteam_result['findings'])} failing finding(s)."
            ),
        }
    )

    intensity_config = INTENSITY_CONFIG.get(intensity, INTENSITY_CONFIG["Standard"])
    record["replay"] = intelligence.build_replay_manifest(record, intensity_config)
    record["replay"]["deepteam"] = {
        "version": record["deepteam"].get("deepteam_version"),
        "target_mode": config.target_mode,
        "target_endpoint_host": record["deepteam"].get("target_endpoint_host"),
        "target_is_simulated": config.target_mode == "secmate_demo",
        "vulnerabilities": list(config.vulnerabilities),
        "attacks": list(config.attacks),
    }

    problems = validate_llm_output.validate_assessment_record(record)
    if problems:
        raise EngineError("Combined assessment record failed validation: " + "; ".join(problems))
    record["progress"].append(
        {
            "stage": "record_validation",
            "status": "Completed",
            "duration_ms": 0,
            "detail": "Merged SecMate and DeepTeam record passed structural validation.",
        }
    )
    return record


def _deepteam_taxonomy_mappings(test_cases: list) -> list:
    mappings = []
    for case in test_cases:
        if case.get("verdict") == "Defended":
            continue
        markers = case.get("matched_markers", {})
        vulnerability_type = markers.get("vulnerability_type") or "Unspecified"
        mappings.append(
            {
                "framework": "DeepTeam",
                "control_id": vulnerability_type,
                "name": case.get("category", "DeepTeam vulnerability"),
                "rationale": (
                    "DeepTeam evaluated the target response for this vulnerability type; "
                    f"the observed outcome was {case.get('verdict', 'unknown')}."
                ),
                "source_type": "test_case",
                "source_ref": case.get("id"),
                "source_category": case.get("category"),
            }
        )
    return mappings
