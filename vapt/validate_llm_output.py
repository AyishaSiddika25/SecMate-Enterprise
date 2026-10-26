"""
vapt/validate_llm_output.py

Defensive validation helpers. Despite the module name (kept from the
original project naming), this validates the STRUCTURE of assessment
records and test-case/finding dicts before they are saved or rendered —
it does not call any LLM. This guards against partially-built records
(e.g. a workflow step that failed) being silently saved as if complete.
"""

REQUIRED_ASSESSMENT_KEYS = {
    "assessment_id", "target", "assessment_type", "intensity",
    "overall_verdict", "test_cases", "vapt_findings", "created_at",
}

REQUIRED_TEST_CASE_KEYS = {"id", "category", "prompt", "simulated_response", "verdict", "explanation"}
REQUIRED_FINDING_KEYS = {"title", "severity", "description", "evidence", "recommendation"}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
VALID_GATES = {"Pass", "Review", "Fail"}
VALID_PROGRESS_STATES = {"Completed", "Skipped", "Failed"}


class ValidationError(Exception):
    pass


def validate_assessment_record(record: dict) -> list:
    """Returns a list of human-readable problems (empty list = valid)."""
    problems = []
    missing = REQUIRED_ASSESSMENT_KEYS - record.keys()
    if missing:
        problems.append(f"Assessment record missing required fields: {sorted(missing)}")

    for i, tc in enumerate(record.get("test_cases", [])):
        tc_missing = REQUIRED_TEST_CASE_KEYS - tc.keys()
        if tc_missing:
            problems.append(f"Test case #{i} missing fields: {sorted(tc_missing)}")

    for i, f in enumerate(record.get("vapt_findings", [])):
        f_missing = REQUIRED_FINDING_KEYS - f.keys()
        if f_missing:
            problems.append(f"VAPT finding #{i} missing fields: {sorted(f_missing)}")
        elif f.get("severity") not in VALID_SEVERITIES:
            problems.append(f"VAPT finding #{i} has unrecognized severity: {f.get('severity')!r}")

        confidence = f.get("confidence")
        if confidence is not None and (
            not isinstance(confidence, dict)
            or not confidence.get("level")
            or not confidence.get("basis")
        ):
            problems.append(f"VAPT finding #{i} has invalid confidence metadata")

        provenance = f.get("provenance")
        if provenance is not None and (
            not isinstance(provenance, dict)
            or not provenance.get("source_type")
            or not provenance.get("source_ref")
        ):
            problems.append(f"VAPT finding #{i} has invalid provenance metadata")

    posture = record.get("posture")
    if posture is not None:
        if not isinstance(posture, dict):
            problems.append("Assessment posture must be an object")
        else:
            score = posture.get("score")
            if not isinstance(score, (int, float)) or not 0 <= score <= 100:
                problems.append("Assessment posture score must be between 0 and 100")
            if posture.get("gate") not in VALID_GATES:
                problems.append(f"Assessment posture has invalid gate: {posture.get('gate')!r}")
            if not isinstance(posture.get("factors"), list):
                problems.append("Assessment posture factors must be a list")

    matrix = record.get("outcome_matrix")
    if matrix is not None:
        if not isinstance(matrix, list):
            problems.append("Outcome matrix must be a list")
        else:
            for i, row in enumerate(matrix):
                if not isinstance(row, dict) or not row.get("category"):
                    problems.append(f"Outcome matrix row #{i} is invalid")

    correlated = record.get("correlated_findings")
    if correlated is not None and not isinstance(correlated, list):
        problems.append("Correlated findings must be a list")

    mappings = record.get("mappings")
    if mappings is not None and not isinstance(mappings, list):
        problems.append("Framework mappings must be a list")

    graph = record.get("relationship_graph")
    if graph is not None and (
        not isinstance(graph, dict)
        or not isinstance(graph.get("nodes"), list)
        or not isinstance(graph.get("edges"), list)
    ):
        problems.append("Relationship graph must contain node and edge lists")

    replay = record.get("replay")
    if replay is not None and not isinstance(replay, dict):
        problems.append("Replay manifest must be an object")

    progress = record.get("progress")
    if progress is not None:
        if not isinstance(progress, list):
            problems.append("Progress must be a list")
        else:
            for i, event in enumerate(progress):
                if not isinstance(event, dict) or event.get("status") not in VALID_PROGRESS_STATES:
                    problems.append(f"Progress event #{i} is invalid")

    return problems


def is_valid_assessment_record(record: dict) -> bool:
    return len(validate_assessment_record(record)) == 0
