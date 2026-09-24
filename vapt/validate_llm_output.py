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

    return problems


def is_valid_assessment_record(record: dict) -> bool:
    return len(validate_assessment_record(record)) == 0
