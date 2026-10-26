"""
core/engine.py

Orchestrates a single assessment run according to the selected workflow:
  - "Red Team-Blue Team Assessment"
  - "VAPT Security Analysis"
  - "Combined Security Assessment"

This module wires together red_team.attack_generator, blue_team.response_evaluator,
and vapt.security_analyzer using their real, existing APIs. It does not
reimplement or mock their logic.
"""

import uuid
from datetime import datetime, timezone
from time import perf_counter

from red_team import attack_generator
from blue_team import response_evaluator
from vapt import security_analyzer, security_decision, validate_llm_output
from core import intelligence

INTENSITY_CONFIG = {
    "Basic": {"categories": 3, "prompts_per_category": 1},
    "Standard": {"categories": 5, "prompts_per_category": 2},
    "Advanced": {"categories": 6, "prompts_per_category": 4},
}

WORKFLOW_RED_BLUE = "Red Team-Blue Team Assessment"
WORKFLOW_VAPT = "VAPT Security Analysis"
WORKFLOW_COMBINED = "Combined Security Assessment"

ALL_WORKFLOWS = [WORKFLOW_RED_BLUE, WORKFLOW_VAPT, WORKFLOW_COMBINED]


class EngineError(Exception):
    pass


def run_assessment(target: str, workflow: str, intensity: str, evidence: str = "") -> dict:
    """
    Executes the selected workflow and returns a fully-formed assessment record
    ready to be validated and persisted.
    """
    if workflow not in ALL_WORKFLOWS:
        raise EngineError(f"Unknown workflow: {workflow}")

    intensity_config = INTENSITY_CONFIG.get(intensity, INTENSITY_CONFIG["Standard"])
    assessment_id = f"SM-{uuid.uuid4().hex[:8].upper()}"
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    test_cases = []
    vapt_findings = []
    notes = []
    progress = []

    def stage(name: str, status: str, started_at: float = None, detail: str = ""):
        duration_ms = None
        if started_at is not None:
            duration_ms = round((perf_counter() - started_at) * 1000, 2)
        progress.append(
            {
                "stage": name,
                "status": status,
                "duration_ms": duration_ms,
                "detail": detail,
            }
        )

    stage("request_validation", "Completed", detail="Workflow, target, and intensity were accepted.")

    run_red_blue = workflow in (WORKFLOW_RED_BLUE, WORKFLOW_COMBINED)
    run_vapt = workflow in (WORKFLOW_VAPT, WORKFLOW_COMBINED)

    if run_red_blue:
        started = perf_counter()
        raw_attacks = attack_generator.generate_attacks(target, intensity_config)
        stage("red_team_generation", "Completed", started, f"Generated {len(raw_attacks)} deterministic adversarial test case(s).")
        started = perf_counter()
        test_cases = response_evaluator.run_blue_team(raw_attacks)
        stage("blue_team_evaluation", "Completed", started, f"Evaluated {len(test_cases)} simulated response(s).")
    else:
        stage("red_team_generation", "Skipped", detail="The selected workflow does not run Red Team generation.")
        stage("blue_team_evaluation", "Skipped", detail="The selected workflow does not run Blue Team evaluation.")

    if run_vapt:
        started = perf_counter()
        if evidence and evidence.strip():
            vapt_findings = security_analyzer.analyze_evidence(
                evidence, related_assessment_id=assessment_id, target=target
            )
        else:
            notes.append(
                "No evidence/context was supplied for VAPT analysis — no rule-based "
                "indicators could be generated for this run."
            )
        # In Combined mode, also derive findings from Blue Team bypass results.
        if workflow == WORKFLOW_COMBINED and test_cases:
            vapt_findings.extend(
                security_analyzer.findings_from_blue_team(
                    test_cases, related_assessment_id=assessment_id, target=target
                )
            )
        stage("vapt_analysis", "Completed", started, f"Produced {len(vapt_findings)} unconfirmed rule-based indicator(s).")
    else:
        stage("vapt_analysis", "Skipped", detail="The selected workflow does not run VAPT evidence analysis.")

    started = perf_counter()
    overall_verdict = security_decision.compute_overall_verdict(test_cases, vapt_findings)
    tc_summary = security_decision.summarize_test_cases(test_cases)
    vapt_findings, correlated_findings = intelligence.enrich_and_correlate_findings(vapt_findings)
    canonical_findings = []
    by_fingerprint = {finding["fingerprint"]: finding for finding in vapt_findings}
    for group in correlated_findings:
        canonical = by_fingerprint.get(group["fingerprint"])
        if canonical:
            canonical_findings.append(canonical)
    posture = security_decision.compute_posture_score(test_cases, canonical_findings, overall_verdict)
    outcome_matrix = intelligence.build_outcome_matrix(test_cases)
    mappings = intelligence.build_framework_mappings(test_cases, vapt_findings)
    relationship_graph = intelligence.build_relationship_graph(target, test_cases, vapt_findings)
    stage("correlation_and_decision", "Completed", started, "Calculated verdict, posture, correlation, mappings, and assessment relationships.")

    record = {
        "schema_version": 2,
        "assessment_id": assessment_id,
        "target": target,
        "assessment_type": workflow,
        "intensity": intensity,
        "overall_verdict": overall_verdict,
        "test_case_count": tc_summary["total"],
        "defended_count": tc_summary["defended"],
        "review_required_count": tc_summary["requires_review"],
        "vapt_indicator_count": len(vapt_findings),
        "test_cases": test_cases,
        "vapt_findings": vapt_findings,
        "evidence_input": evidence or "",
        "review_status": "Pending Review",
        "review_notes": "",
        "status": "Completed",
        "created_at": created_at,
        "notes": notes,
        "posture": posture,
        "outcome_matrix": outcome_matrix,
        "correlated_findings": correlated_findings,
        "mappings": mappings,
        "relationship_graph": relationship_graph,
        "progress": progress,
    }

    record["replay"] = intelligence.build_replay_manifest(record, intensity_config)

    validation_started = perf_counter()
    problems = validate_llm_output.validate_assessment_record(record)
    if problems:
        raise EngineError("Assessment record failed validation: " + "; ".join(problems))
    stage("record_validation", "Completed", validation_started, "Assessment record passed structural validation.")

    return record
