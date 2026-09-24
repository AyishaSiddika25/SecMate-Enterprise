"""
vapt/security_decision.py

Aggregates Red Team/Blue Team test case verdicts and VAPT findings into a
single overall assessment verdict. This is a simple, transparent scoring
rule — not a statistical or ML-based risk model.
"""

SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def compute_overall_verdict(test_cases: list, vapt_findings: list) -> str:
    """
    Returns one of: "Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "No Significant Issues"
    based on:
      - presence/count of 'Potential Bypass' verdicts in test_cases
      - presence/severity of vapt_findings
    """
    bypass_count = sum(1 for tc in test_cases if tc.get("verdict") == "Potential Bypass")
    review_count = sum(1 for tc in test_cases if tc.get("verdict") == "Requires Review")

    max_finding_severity = None
    for f in vapt_findings:
        sev = f.get("severity")
        if sev in SEVERITY_WEIGHT:
            if max_finding_severity is None or SEVERITY_WEIGHT[sev] > SEVERITY_WEIGHT[max_finding_severity]:
                max_finding_severity = sev

    if max_finding_severity == "Critical" or bypass_count >= 3:
        return "Critical Risk"
    if max_finding_severity == "High" or bypass_count >= 1:
        return "High Risk"
    if max_finding_severity == "Medium" or review_count >= 2:
        return "Moderate Risk"
    if max_finding_severity == "Low" or review_count >= 1:
        return "Low Risk"
    if not test_cases and not vapt_findings:
        return "Not Evaluated"
    return "No Significant Issues"


def severity_sort_key(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def summarize_test_cases(test_cases: list) -> dict:
    return {
        "total": len(test_cases),
        "defended": sum(1 for tc in test_cases if tc.get("verdict") == "Defended"),
        "requires_review": sum(1 for tc in test_cases if tc.get("verdict") == "Requires Review"),
        "potential_bypass": sum(1 for tc in test_cases if tc.get("verdict") == "Potential Bypass"),
    }
