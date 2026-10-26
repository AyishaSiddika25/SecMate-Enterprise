"""
app/streamlit_app.py

SecMate — AI-Assisted Security Assessment Platform (Demo / Simulation Prototype)

Run with:
    python -m streamlit run app/streamlit_app.py

This file contains ONLY UI/orchestration logic. All actual assessment logic
lives in core/, red_team/, blue_team/, and vapt/ — see those modules.
"""

import os
import sys
import json
import yaml
import streamlit as st
import pandas as pd

# --- Make project root importable regardless of the working directory ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core import database, engine, intelligence
from vapt import security_decision

CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "styles.css")
SETTINGS_PATH = os.path.join(PROJECT_ROOT, "config", "settings.yaml")

st.set_page_config(
    page_title="SecMate",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# Setup helpers
# ============================================================

def load_css():
    try:
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning(
            f"⚠️ Developer notice: stylesheet not found at `{CSS_PATH}`. "
            "The app will run with default Streamlit styling instead of the SecMate theme."
        )
    except OSError as e:
        st.warning(f"⚠️ Developer notice: failed to load stylesheet ({e}). Using default styling.")


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (FileNotFoundError, yaml.YAMLError):
        return {}


def save_settings(settings: dict):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, sort_keys=False)


def init_state():
    defaults = {
        "logged_in": False,
        "user_email": "",
        "org": "",
        "page": "Dashboard",
        "selected_assessment_id": None,
        "confirm_delete_id": None,
        "last_result": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def ensure_db():
    try:
        database.init_db()
        return True
    except database.DatabaseError as e:
        st.error(f"Database initialization failed: {e}")
        return False


# ============================================================
# Reusable UI fragments
# ============================================================

SEVERITY_CLASS = {
    "Critical": "sm-badge-critical",
    "High": "sm-badge-high",
    "Medium": "sm-badge-medium",
    "Low": "sm-badge-low",
    "Info": "sm-badge-info",
}

VERDICT_CLASS = {
    "Defended": "sm-badge-defended",
    "Requires Review": "sm-badge-review",
    "Potential Bypass": "sm-badge-bypass",
}


def badge(text: str, css_class: str) -> str:
    return f'<span class="sm-badge {css_class}">{text}</span>'


def severity_badge(severity: str) -> str:
    return badge(severity, SEVERITY_CLASS.get(severity, "sm-badge-info"))


def verdict_badge(verdict: str) -> str:
    return badge(verdict, VERDICT_CLASS.get(verdict, "sm-badge-info"))


def metric_card(label: str, value):
    st.markdown(
        f"""<div class="sm-metric-card">
                <div class="sm-metric-label">{label}</div>
                <div class="sm-metric-value">{value}</div>
            </div>""",
        unsafe_allow_html=True,
    )


def empty_state(message: str, icon: str = "🗂️"):
    st.markdown(
        f"""<div class="sm-empty-state">
                <div style="font-size:2rem;">{icon}</div>
                <div style="margin-top:0.5rem;">{message}</div>
            </div>""",
        unsafe_allow_html=True,
    )


def demo_banner():
    st.markdown('<div class="sm-demo-banner">🧪 DEMO / SIMULATION MODE — no live targets are contacted</div>', unsafe_allow_html=True)


# ============================================================
# Login page
# ============================================================

def login_page():
    load_css()
    left, right = st.columns([1.65, 0.78], gap="small")

    with left:
        st.markdown(
            """
            <div class="sm-login-marker-left"></div>
            <div class="sm-login-top">
              <div class="sm-brand sm-brand-large">
                <div class="sm-logo"><span>◆</span></div>
                <div>
                  <div class="sm-brand-name">SecMate</div>
                  <div class="sm-brand-tag">Secure AI. Trust What Runs.</div>
                </div>
              </div>
              <div class="sm-status-pill"><span></span> Production &nbsp; <b>Enterprise Gateway</b></div>
            </div>
            <div class="sm-login-copy">
              <div class="sm-login-headline">
                Adversarial testing for<br/>
                AI agents, <span class="accent">built for enterprise.</span>
              </div>
            </div>
            <div class="sm-network"></div>
            <div class="sm-login-footer">
              <b>▣ Enterprise Security</b>
              <span class="sep">|</span>
              Your credentials are encrypted and never included in audit exports.
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        st.markdown('<div class="sm-login-marker-right"></div>', unsafe_allow_html=True)
        st.markdown("## Welcome back")
        st.markdown('<div class="sm-login-sub">Sign in to your SecMate account</div>', unsafe_allow_html=True)

        org = st.selectbox(
            "Organization",
            ["Paramount Computer Systems", "SecMate Demo Workspace", "Acme Security Labs", "Personal Sandbox"],
        )
        email = st.text_input("Work email", placeholder="you@company.com")
        password = st.text_input("Password", type="password", placeholder="Enter your password")

        st.markdown('<div class="sm-forgot">Forgot password?</div>', unsafe_allow_html=True)

        sign_in = st.button("Sign In", use_container_width=True)
        st.markdown('<div class="sm-or"><span>or</span></div>', unsafe_allow_html=True)
        sso = st.button("Sign in with SSO", use_container_width=True, type="secondary")
        st.markdown(
            '<div class="sm-sso-note">Recommended for enterprise organizations</div>',
            unsafe_allow_html=True,
        )

        if sign_in or sso:
            if sign_in and not email:
                st.error("Enter a work email to continue (demo mode accepts any value).")
            else:
                st.session_state.logged_in = True
                st.session_state.user_email = email or "demo.user@secmate.local"
                st.session_state.org = org
                st.rerun()

        st.markdown(
            '<div class="sm-admin-link">New to SecMate? <span>Contact your administrator</span></div>',
            unsafe_allow_html=True,
        )


# ============================================================
# Sidebar navigation
# ============================================================

NAV_ITEMS = [
    ("Dashboard", "◉"),
    ("New Assessment", "▣"),
    ("Assessment History", "◷"),
    ("VAPT Findings", "⌁"),
    ("Attack Relationships", "⌁"),
    ("Reports", "▤"),
    ("Settings", "⚙"),
]


def sanitized_export(value):
    """Redact credential-like values from analyst downloads without mutating records."""
    if isinstance(value, dict):
        return {key: sanitized_export(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitized_export(item) for item in value]
    if isinstance(value, str):
        return intelligence.redact_sensitive_text(value)
    return value


def sidebar():
    with st.sidebar:
        st.markdown(
            """<div class="sm-side-brand">
                <div class="sm-logo small"><span>◆</span></div>
                <div><div class="sm-brand-name">SecMate</div><div class="sm-brand-tag">AI Security Platform</div></div>
            </div>""",
            unsafe_allow_html=True,
        )
        st.markdown('<div class="sm-side-section">OPERATE</div>', unsafe_allow_html=True)

        for label, icon in NAV_ITEMS:
            btn_type = "primary" if st.session_state.page == label else "secondary"
            if st.button(f"{icon}  {label}", use_container_width=True, key=f"nav_{label}", type=btn_type):
                st.session_state.page = label
                st.rerun()

        st.markdown('<div class="sm-side-section sm-side-bottom">GOVERNANCE & STANDARDS</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="sm-side-user"><div class="sm-avatar">◇</div><div><b>Security Operator</b><span>Enterprise workspace</span></div></div>',
            unsafe_allow_html=True,
        )
        if st.button("↩ Sign Out", use_container_width=True, type="secondary"):
            st.session_state.logged_in = False
            st.rerun()


# ============================================================
# Dashboard page
# ============================================================

def dashboard_page():
    try:
        metrics = database.get_metrics()
        records = database.get_all_assessments()
    except database.DatabaseError as e:
        st.error(f"Could not load dashboard data: {e}")
        return

    st.markdown(
        """<div class="sm-page-head">
            <div><h1>Security Posture</h1>
            <div class="sm-page-sub">Explainable decisions from completed SecMate assessments</div></div>
            <div class="sm-project-pill"><span></span> Project SecMate <b>• active</b></div>
        </div>""",
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Open Findings", metrics["vapt_indicators"])
        st.caption("↑ Based on stored assessments")
    with c2:
        metric_card("Critical Exposure", sum(
            1 for r in records for f in r.get("vapt_findings", []) if f.get("severity") == "Critical"
        ))
        st.caption("Requires analyst validation")
    with c3:
        metric_card("Assessments", metrics["total_assessments"])
        st.caption("Stored assessment records")
    with c4:
        metric_card("Completed", metrics["completed"])
        st.caption("Assessment runs completed")

    st.markdown('<div class="sm-section-gap"></div>', unsafe_allow_html=True)

    left, right = st.columns([1.15, 1.85], gap="large")
    with left:
        st.markdown('<div class="sm-card-title">Findings by severity <span>Stored indicators</span></div>', unsafe_allow_html=True)
        severity_counts = {k: 0 for k in ["Critical", "High", "Medium", "Low"]}
        for r in records:
            for f in r.get("vapt_findings", []):
                if f.get("severity") in severity_counts:
                    severity_counts[f["severity"]] += 1
        total = sum(severity_counts.values())
        if total:
            st.markdown(
                f'<div class="sm-risk-donut"><div><strong>{total}</strong><span>OPEN</span></div></div>',
                unsafe_allow_html=True,
            )
            for sev, count in severity_counts.items():
                st.markdown(f'<div class="sm-risk-row"><span class="dot {sev.lower()}"></span>{sev}<b>{count}</b></div>', unsafe_allow_html=True)
        else:
            empty_state("No findings yet. Run an assessment with approved evidence.", icon="•")

    with right:
        st.markdown('<div class="sm-card-title">Posture trend <span>Assessment history</span></div>', unsafe_allow_html=True)
        trend_rows = []
        for idx, r in enumerate(reversed(records[-10:]), start=1):
            score = r.get("posture", {}).get("score")
            if isinstance(score, (int, float)):
                trend_rows.append({"Run": idx, "Posture score": score})
        if trend_rows:
            try:
                import plotly.express as px
                df = pd.DataFrame(trend_rows)
                fig = px.line(df, x="Run", y="Posture score", markers=True)
                fig.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#94A3B8", showlegend=False,
                    margin=dict(t=10,b=10,l=10,r=10), xaxis_title=None, yaxis_title=None,
                )
                fig.update_traces(line_width=3)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            except ImportError:
                st.line_chart(pd.DataFrame(trend_rows).set_index("Run"))
        else:
            empty_state("Run assessments to populate the risk trend.")

    st.markdown('<div class="sm-section-gap"></div>', unsafe_allow_html=True)
    a, b = st.columns(2, gap="large")
    with a:
        st.markdown('<div class="sm-card-title">Assessment relationships <span>Latest evidence-backed links</span></div>', unsafe_allow_html=True)
        if records:
            latest = records[0]
            graph = latest.get("relationship_graph", {})
            nodes = {node.get("id"): node for node in graph.get("nodes", [])}
            edges = graph.get("edges", [])
            if edges:
                for i, edge in enumerate(edges[:4], 1):
                    source = nodes.get(edge.get("from"), {})
                    destination = nodes.get(edge.get("to"), {})
                    st.markdown(
                        f'<div class="sm-list-row"><span class="rank">{i}</span><div><b>{source.get("label","Node")} → {destination.get("label","Node")}</b><small>{edge.get("relationship","related to")}</small></div><span class="chev">›</span></div>',
                        unsafe_allow_html=True,
                    )
            else:
                empty_state("The latest assessment contains no relationship edges.")
        else:
            empty_state("No assessment data yet.")
    with b:
        st.markdown('<div class="sm-card-title">Recent agent activity <span>Latest assessment runs</span></div>', unsafe_allow_html=True)
        if records:
            for r in records[:5]:
                st.markdown(
                    f'<div class="sm-activity"><span class="activity-dot"></span><div><b>{r["assessment_type"]}</b><small>{r["target"]} · {r["created_at"]}</small></div></div>',
                    unsafe_allow_html=True,
                )
        else:
            empty_state("No assessment activity yet.")


# ============================================================
# Assessment Operations page
# ============================================================

def render_test_case(tc: dict):
    with st.expander(f"{tc['id']} · {tc['category']} — {tc['verdict']}"):
        st.markdown(f"**Attack category:** {tc['category']}")
        st.markdown("**Test prompt:**")
        st.markdown(f'<div class="sm-mono">{tc["prompt"]}</div>', unsafe_allow_html=True)
        st.markdown("**Simulated target response:**")
        st.markdown(f'<div class="sm-mono">{tc["simulated_response"]}</div>', unsafe_allow_html=True)
        st.markdown(f"**Blue Team verdict:** {verdict_badge(tc['verdict'])}", unsafe_allow_html=True)
        st.markdown(f"**Explanation:** {tc['explanation']}")


def render_finding(f: dict):
    with st.expander(f"{f['title']} — {f['severity']}"):
        st.markdown(severity_badge(f["severity"]), unsafe_allow_html=True)
        st.markdown(f"**Finding ID:** `{f.get('finding_id', 'Legacy record')}`")
        st.markdown(f"**Description:** {f['description']}")
        st.markdown("**Evidence:**")
        st.markdown(f'<div class="sm-mono">{f["evidence"]}</div>', unsafe_allow_html=True)
        st.markdown(f"**Recommendation:** {f['recommendation']}")
        provenance = f.get("provenance", {})
        confidence = f.get("confidence", {})
        span = f.get("evidence_span", {})
        st.caption(
            f"Status: {f.get('status', 'Unconfirmed')} · "
            f"Source: {provenance.get('source_type', 'not recorded')} / {provenance.get('source_ref', '—')} · "
            f"Confidence: {confidence.get('level', 'not recorded')} · "
            f"Evidence span: {span.get('start', '—')}:{span.get('end', '—')}"
        )


def render_result(record: dict):
    st.success(f"Assessment `{record['assessment_id']}` completed.")
    for note in record.get("notes", []):
        st.info(note)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Overall Verdict", record["overall_verdict"])
    with c2:
        metric_card("Test Cases", record["test_case_count"])
    with c3:
        metric_card("Defended", record["defended_count"])
    with c4:
        metric_card("VAPT Indicators", record["vapt_indicator_count"])

    st.caption(
        "Simulated results reflect rule-based evaluation of templated adversarial prompts "
        "against a simulated target — this does NOT represent real-world exploit verification."
    )

    posture = record.get("posture", {})
    st.subheader("Explainable Security Posture")
    p1, p2, p3 = st.columns(3)
    p1.metric("Posture score", f"{posture.get('score', '—')} / 100")
    p2.metric("Security gate", posture.get("gate", "Review"))
    p3.metric("Decision model", posture.get("model", "Legacy record"))
    st.write(posture.get("rationale", "This legacy assessment does not contain posture rationale."))
    factors = posture.get("factors", [])
    if factors:
        st.dataframe(
            pd.DataFrame([
                {
                    "Factor": factor.get("label"),
                    "Impact": factor.get("impact"),
                    "Reason": factor.get("reason"),
                    "Sources": ", ".join(filter(None, factor.get("source_refs", []))),
                }
                for factor in factors
            ]),
            use_container_width=True,
            hide_index=True,
        )

    if record.get("progress"):
        st.subheader("Server-Reported Execution Status")
        st.dataframe(
            pd.DataFrame([
                {
                    "Stage": step.get("stage", "").replace("_", " ").title(),
                    "Status": step.get("status"),
                    "Duration (ms)": step.get("duration_ms"),
                    "Detail": step.get("detail"),
                }
                for step in record["progress"]
            ]),
            use_container_width=True,
            hide_index=True,
        )

    if record.get("outcome_matrix"):
        st.subheader("Red Team vs Blue Team Outcome Matrix")
        st.dataframe(pd.DataFrame(record["outcome_matrix"]), use_container_width=True, hide_index=True)

    if record["test_cases"]:
        st.subheader("Red Team / Blue Team Results")
        for tc in record["test_cases"]:
            render_test_case(tc)

    if record["vapt_findings"]:
        st.subheader("Evidence Explorer")
        correlated = record.get("correlated_findings", [])
        if correlated:
            st.caption(
                f"{len(record['vapt_findings'])} original indicator(s) correlated into "
                f"{len(correlated)} unique finding(s)."
            )
        unique_fingerprints = set()
        for f in record["vapt_findings"]:
            fingerprint = f.get("fingerprint")
            if fingerprint and fingerprint in unique_fingerprints:
                continue
            unique_fingerprints.add(fingerprint)
            render_finding(f)
    elif record["assessment_type"] in (engine.WORKFLOW_VAPT, engine.WORKFLOW_COMBINED):
        empty_state("No VAPT indicators were generated for this run.")

    if record.get("mappings"):
        st.subheader("MITRE / OWASP / CWE Mappings")
        st.dataframe(pd.DataFrame(record["mappings"]), use_container_width=True, hide_index=True)

    export_record = sanitized_export(record)
    st.download_button(
        "⬇ Download Redacted JSON Report",
        data=json.dumps(export_record, indent=2),
        file_name=f"{record['assessment_id']}_report.json",
        mime="application/json",
    )
    if record.get("replay"):
        st.download_button(
            "⬇ Download Reproducibility Package",
            data=json.dumps(record["replay"], indent=2),
            file_name=f"{record['assessment_id']}_replay.json",
            mime="application/json",
        )


def assessment_operations_page():
    st.markdown(
        """<div class="sm-page-head">
            <div><h1>Onboard Application</h1>
            <div class="sm-page-sub">Register an application, characterize its stack, and scope AI security testing.</div></div>
            <div class="sm-project-pill"><span></span> Project SecMate <b>• active</b></div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.markdown(
        """<div class="sm-stepper">
            <div class="active"><span>01</span>Identify</div>
            <div><span>02</span>Characterize</div>
            <div><span>03</span>Scope & Role</div>
            <div><span>04</span>CVE & standards</div>
            <div><span>05</span>Review</div>
        </div>""",
        unsafe_allow_html=True,
    )

    settings = load_settings()
    with st.form("new_assessment_form"):
        st.markdown('<div class="sm-form-card"><div class="sm-form-title">Application identity <span>who owns it & what data it touches</span></div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            target = st.text_input("Application name", value=settings.get("default_target", "NovaMind AI"))
        with c2:
            owner = st.text_input("Owner / team", value="Security Engineering")
        c3, c4 = st.columns(2)
        with c3:
            business = st.selectbox("Business criticality", ["Tier 1 · mission critical", "Tier 2 · important", "Tier 3 · standard"])
        with c4:
            environment = st.selectbox("Environment", ["Production", "Staging", "Development"])
        st.markdown('<div class="sm-field-label">Data classification</div>', unsafe_allow_html=True)
        tags = st.multiselect(
            "Data classification",
            ["Candidate data (PII)", "PII (health)", "Internet-facing", "Exposes a REST API", "Contains a GenAI / LLM feature"],
            default=["Internet-facing"],
            label_visibility="collapsed",
        )
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="sm-form-card"><div class="sm-form-title">Assessment scope <span>select the security workflow to run</span></div>', unsafe_allow_html=True)
        workflow = st.selectbox("Assessment workflow", engine.ALL_WORKFLOWS,
            index=engine.ALL_WORKFLOWS.index(settings.get("default_workflow", engine.WORKFLOW_COMBINED))
            if settings.get("default_workflow") in engine.ALL_WORKFLOWS else 2)
        intensity = st.select_slider("Assessment intensity", options=["Basic", "Standard", "Advanced"],
                                      value=settings.get("default_intensity", "Standard"))
        evidence = st.text_area("Approved evidence / context", placeholder="Paste approved test observations, logs, or transcript excerpts...", height=120)
        submitted = st.form_submit_button("Continue & Run Assessment", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if submitted:
        if not target.strip():
            st.error("Application name is required.")
        else:
            with st.spinner("Running assessment..."):
                try:
                    record = engine.run_assessment(target.strip(), workflow, intensity, evidence)
                    database.save_assessment(record)
                    st.session_state.last_result = record
                except engine.EngineError as e:
                    st.error(f"Assessment failed: {e}")
                    st.session_state.last_result = None
                except database.DatabaseError as e:
                    st.error(f"Assessment ran but could not be saved: {e}")
                    st.session_state.last_result = None

    if st.session_state.last_result:
        st.markdown('<div class="sm-section-gap"></div>', unsafe_allow_html=True)
        render_result(st.session_state.last_result)


def render_history_tab():
    try:
        all_records = database.get_all_assessments()
    except database.DatabaseError as e:
        st.error(f"Could not load history: {e}")
        return

    if not all_records:
        empty_state("No assessments have been run yet.")
        return

    st.subheader("Assessment Comparison & Regression Tracking")
    if len(all_records) < 2:
        st.info("Run at least two assessments to compare regressions.")
    else:
        record_ids = [record["assessment_id"] for record in all_records]
        compare_left, compare_right = st.columns(2)
        with compare_left:
            baseline_id = st.selectbox("Baseline assessment", record_ids, index=1, key="compare_baseline")
        with compare_right:
            candidate_id = st.selectbox("Candidate assessment", record_ids, index=0, key="compare_candidate")
        if baseline_id == candidate_id:
            st.warning("Choose two different completed assessments.")
        elif st.button("Compare assessments", key="run_comparison"):
            baseline = next(record for record in all_records if record["assessment_id"] == baseline_id)
            candidate = next(record for record in all_records if record["assessment_id"] == candidate_id)
            try:
                comparison = intelligence.compare_assessments(baseline, candidate)
                d1, d2, d3, d4 = st.columns(4)
                d1.metric("New", len(comparison["new_findings"]))
                d2.metric("Resolved", len(comparison["resolved_findings"]))
                d3.metric("Unchanged", len(comparison["unchanged_findings"]))
                d4.metric("Severity changed", len(comparison["severity_changed_findings"]))
                st.write(
                    f"**Verdict:** {comparison['verdict']['before']} → {comparison['verdict']['after']} · "
                    f"**Posture score:** {comparison['posture_score']['before']} → "
                    f"{comparison['posture_score']['after']} (Δ {comparison['posture_score']['delta']})"
                )
                for label, key in (
                    ("New findings", "new_findings"),
                    ("Resolved findings", "resolved_findings"),
                    ("Unchanged findings", "unchanged_findings"),
                    ("Severity changes", "severity_changed_findings"),
                ):
                    with st.expander(f"{label} ({len(comparison[key])})"):
                        if comparison[key]:
                            st.json(comparison[key])
                        else:
                            st.caption("None")
            except ValueError as exc:
                st.error(f"Could not compare assessments: {exc}")

    st.markdown('<hr class="sm-divider"/>', unsafe_allow_html=True)

    f1, f2, f3 = st.columns([2, 1, 1])
    with f1:
        query = st.text_input("Search by Assessment ID or target", key="hist_search")
    with f2:
        type_filter = st.selectbox("Type", ["All"] + engine.ALL_WORKFLOWS, key="hist_type")
    with f3:
        status_filter = st.selectbox(
            "Review Status", ["All", "Pending Review", "Reviewed - No Action", "Reviewed - Escalated"], key="hist_status"
        )

    filtered = database.search_assessments(query, type_filter, status_filter)
    st.caption(f"Showing {len(filtered)} of {len(all_records)} assessments")

    table_rows = [
        {
            "Assessment ID": r["assessment_id"],
            "Target": r["target"],
            "Type": r["assessment_type"],
            "Intensity": r["intensity"],
            "Verdict": r["overall_verdict"],
            "Review Status": r["review_status"],
            "Timestamp": r["created_at"],
        }
        for r in filtered
    ]
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    st.download_button(
        "⬇ Export Redacted History (JSON)",
        data=json.dumps(sanitized_export(filtered), indent=2),
        file_name="secmate_filtered_history.json",
        mime="application/json",
        key="export_filtered",
    )

    st.markdown('<hr class="sm-divider"/>', unsafe_allow_html=True)
    st.subheader("Inspect Assessment")

    ids = [r["assessment_id"] for r in filtered]
    if not ids:
        empty_state("No assessments match the current filters.")
        return

    selected_id = st.selectbox("Select an assessment to inspect", ids, key="hist_select")
    record = database.get_assessment_by_id(selected_id)
    if not record:
        st.warning("Selected assessment could not be found (it may have just been deleted).")
        return

    render_result(record)

    st.markdown('<hr class="sm-divider"/>', unsafe_allow_html=True)
    st.subheader("Analyst Review")

    rc1, rc2 = st.columns(2)
    with rc1:
        new_status = st.selectbox(
            "Review Status",
            ["Pending Review", "Reviewed - No Action", "Reviewed - Escalated"],
            index=["Pending Review", "Reviewed - No Action", "Reviewed - Escalated"].index(record["review_status"])
            if record["review_status"] in ["Pending Review", "Reviewed - No Action", "Reviewed - Escalated"] else 0,
            key=f"status_{selected_id}",
        )
    with rc2:
        st.write("")

    new_notes = st.text_area("Review Notes", value=record.get("review_notes", ""), key=f"notes_{selected_id}", height=100)

    save_col, export_col, delete_col = st.columns(3)
    with save_col:
        if st.button("💾 Save Review", use_container_width=True, key=f"save_{selected_id}"):
            try:
                database.update_review(selected_id, review_status=new_status, review_notes=new_notes)
                st.success("Review updated.")
                st.rerun()
            except database.DatabaseError as e:
                st.error(f"Failed to update review: {e}")
    with export_col:
        st.download_button(
            "⬇ Export Redacted Assessment",
            data=json.dumps(sanitized_export(record), indent=2),
            file_name=f"{selected_id}_report.json",
            mime="application/json",
            use_container_width=True,
            key=f"export_{selected_id}",
        )
    with delete_col:
        if st.button("🗑️ Delete Assessment", use_container_width=True, type="secondary", key=f"del_{selected_id}"):
            st.session_state.confirm_delete_id = selected_id
            st.rerun()

    if st.session_state.confirm_delete_id == selected_id:
        st.warning(f"Are you sure you want to permanently delete `{selected_id}`? This cannot be undone.")
        cc1, cc2 = st.columns(2)
        with cc1:
            if st.button("✅ Confirm Delete", use_container_width=True, key=f"confirm_del_{selected_id}"):
                try:
                    database.delete_assessment(selected_id)
                    st.session_state.confirm_delete_id = None
                    st.success("Assessment deleted.")
                    st.rerun()
                except database.DatabaseError as e:
                    st.error(f"Failed to delete: {e}")
        with cc2:
            if st.button("Cancel", use_container_width=True, key=f"cancel_del_{selected_id}"):
                st.session_state.confirm_delete_id = None
                st.rerun()


# ============================================================
# VAPT Findings page
# ============================================================

def vapt_findings_page():
    st.markdown(
        """<div class="sm-page-head">
            <div><h1>Findings</h1>
            <div class="sm-page-sub">Validated security indicators with evidence, severity, and assessment mapping.</div></div>
            <div class="sm-project-pill"><span></span> Project SecMate <b>• active</b></div>
        </div>""",
        unsafe_allow_html=True,
    )

    try:
        records = database.get_all_assessments()
    except database.DatabaseError as e:
        st.error(f"Could not load findings: {e}")
        return

    finding_groups = {}
    for r in records:
        for f in r.get("vapt_findings", []):
            enriched = dict(f)
            enriched["related_assessment_id"] = enriched.get("related_assessment_id") or r["assessment_id"]
            enriched["target"] = enriched.get("target") or r["target"]
            fingerprint = enriched.get("fingerprint") or intelligence.finding_fingerprint(enriched)
            if fingerprint not in finding_groups:
                enriched["fingerprint"] = fingerprint
                enriched["assessment_ids"] = []
                enriched["occurrence_count"] = 0
                finding_groups[fingerprint] = enriched
            group = finding_groups[fingerprint]
            group["occurrence_count"] += 1
            if r["assessment_id"] not in group["assessment_ids"]:
                group["assessment_ids"].append(r["assessment_id"])

    all_findings = list(finding_groups.values())

    if not all_findings:
        empty_state("No findings recorded yet. Run a VAPT or Combined assessment with approved evidence.", icon="🔍")
        return

    severities = ["All"] + sorted({f["severity"] for f in all_findings}, key=security_decision.severity_sort_key)
    c1, c2 = st.columns([3,1])
    with c1:
        query = st.text_input("Search findings", placeholder="Search finding, asset, or assessment...")
    with c2:
        sev_filter = st.selectbox("Severity", severities)

    filtered = [f for f in all_findings if sev_filter == "All" or f["severity"] == sev_filter]
    if query.strip():
        q = query.lower()
        filtered = [f for f in filtered if q in json.dumps(f).lower()]
    filtered = sorted(filtered, key=lambda f: security_decision.severity_sort_key(f["severity"]))

    st.markdown(f'<div class="sm-table-meta">{len(filtered)} findings <span>• unconfirmed rule-based indicators</span></div>', unsafe_allow_html=True)
    rows = []
    for f in filtered:
        rows.append({
            "Severity": f.get("severity","Info"),
            "Finding": f.get("title","Security indicator"),
            "CVSS": f.get("cvss","—"),
            "Asset": f.get("target","—"),
            "Status": f.get("status","Open"),
            "Occurrences": f.get("occurrence_count", 1),
            "Assessments": len(f.get("assessment_ids", [])),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=min(520, 120 + len(rows)*42))

    st.markdown('<div class="sm-section-gap"></div>', unsafe_allow_html=True)
    for f in filtered:
        with st.expander(f'{f.get("severity","Info").upper()} · {f.get("title","Security indicator")}'):
            st.markdown(severity_badge(f["severity"]), unsafe_allow_html=True)
            st.markdown(f"**Related assessments:** `{', '.join(f.get('assessment_ids', []))}`")
            st.markdown(f"**Description:** {f.get('description','')}")
            st.markdown("**Evidence:**")
            st.markdown(f'<div class="sm-mono">{f.get("evidence","")}</div>', unsafe_allow_html=True)
            st.markdown(f"**Recommendation:** {f.get('recommendation','')}")
            provenance = f.get("provenance", {})
            confidence = f.get("confidence", {})
            span = f.get("evidence_span", {})
            st.caption(
                f"Validation status: {f.get('status', 'Rule-Based Indicator (Unconfirmed)')} · "
                f"Source: {provenance.get('source_type', 'not recorded')} / {provenance.get('source_ref', '—')} · "
                f"Confidence: {confidence.get('level', 'not recorded')} · "
                f"Span: {span.get('start', '—')}:{span.get('end', '—')} · "
                f"Occurrences: {f.get('occurrence_count', 1)}"
            )


# ============================================================
# Reports page
# ============================================================

def attack_relationships_page():
    st.markdown(
        """<div class="sm-page-head">
            <div><h1>Assessment Relationships</h1>
            <div class="sm-page-sub">Inspect evidence-backed links between targets, tests, and findings.</div></div>
            <div class="sm-project-pill"><span></span> Project SecMate <b>• active</b></div>
        </div>""",
        unsafe_allow_html=True,
    )
    try:
        records = database.get_all_assessments()
    except database.DatabaseError as e:
        st.error(f"Could not load assessment relationships: {e}")
        return
    if not records:
        empty_state("No relationship graph is available. Run an assessment first.", icon="⛓")
        return
    selected_id = st.selectbox("Assessment", [record["assessment_id"] for record in records], key="relationship_assessment")
    record = next(item for item in records if item["assessment_id"] == selected_id)
    graph = record.get("relationship_graph", {})
    nodes = {node.get("id"): node for node in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    st.info(graph.get("disclaimer", "Relationships represent assessment observations, not confirmed exploitability."))
    if not edges:
        empty_state("This assessment contains no reviewable relationships.", icon="⛓")
        return
    for edge in edges:
        source = nodes.get(edge.get("from"), {"label": edge.get("from"), "type": "unknown"})
        destination = nodes.get(edge.get("to"), {"label": edge.get("to"), "type": "unknown"})
        left, relation, right = st.columns([2, 1, 2])
        left.markdown(f"**{source.get('label', 'Unknown')}**  \n`{source.get('type', 'node')}`")
        relation.markdown(f"→ **{edge.get('relationship', 'related to')}** →")
        right.markdown(
            f"**{destination.get('label', 'Unknown')}**  \n"
            f"`{destination.get('type', 'node')}` · {destination.get('status', 'observed')}"
        )

def reports_page():
    st.title("Reports")
    st.markdown(
        '<div class="sm-subtitle">Executive, analyst, and framework views generated from actual stored assessment records.</div>',
        unsafe_allow_html=True,
    )

    try:
        records = database.get_all_assessments()
    except database.DatabaseError as e:
        st.error(f"Could not load reports: {e}")
        return

    if not records:
        empty_state("No reports available yet. Run an assessment to generate one.", icon="📄")
        return

    selected_id = st.selectbox("Assessment", [record["assessment_id"] for record in records], key="report_assessment")
    record = next(item for item in records if item["assessment_id"] == selected_id)
    posture = record.get("posture", {})
    correlated = record.get("correlated_findings", [])

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Posture score", f"{posture.get('score', '—')} / 100")
    r2.metric("Security gate", posture.get("gate", "Review"))
    r3.metric("Unique findings", len(correlated) or len(record.get("vapt_findings", [])))
    r4.metric("Test cases", record.get("test_case_count", 0))

    executive, analyst, frameworks = st.tabs(["Executive summary", "Analyst detail", "Framework mappings"])
    with executive:
        st.subheader(f"{record['target']} — Executive Security Summary")
        st.caption(f"{record['assessment_id']} · {record['created_at']} · CONFIDENTIAL")
        st.write(
            f"SecMate completed a **{record['assessment_type']}** at **{record['intensity']}** intensity. "
            f"The security gate is **{posture.get('gate', 'Review')}** and the engine verdict is "
            f"**{record.get('overall_verdict', 'Unknown')}**."
        )
        st.markdown("#### Decision basis")
        st.write(posture.get("rationale", "This legacy assessment does not include an explainable posture rationale."))
        for factor in posture.get("factors", []):
            st.write(f"- **{factor.get('label')}** ({factor.get('impact', 0)}): {factor.get('reason')}")
        st.markdown("#### Management recommendation")
        if correlated:
            top = correlated[0]
            st.write(
                f"Prioritize analyst validation of **{top.get('severity', 'Info')} — {top.get('title', 'Security indicator')}**. "
                f"{top.get('recommendation') or 'Determine the affected control and remediation owner.'}"
            )
        else:
            st.write("No VAPT indicators were generated. Confirm that assessment coverage and any ambiguous test outcomes are acceptable before approval.")

    with analyst:
        st.subheader("Technical findings and evidence")
        if record.get("vapt_findings"):
            seen = set()
            for finding in record["vapt_findings"]:
                if finding.get("fingerprint") in seen:
                    continue
                seen.add(finding.get("fingerprint"))
                render_finding(finding)
        else:
            empty_state("No VAPT indicators were generated for this assessment.")
        st.subheader("Red Team / Blue Team outcomes")
        if record.get("outcome_matrix"):
            st.dataframe(pd.DataFrame(record["outcome_matrix"]), use_container_width=True, hide_index=True)
        else:
            st.caption("No adversarial test cases were executed for this workflow.")

    with frameworks:
        st.subheader("Evidence-supported mappings")
        if record.get("mappings"):
            st.dataframe(pd.DataFrame(record["mappings"]), use_container_width=True, hide_index=True)
            st.caption("Mappings describe observed categories and indicators; they do not claim full framework compliance.")
        else:
            empty_state("No justified framework mappings were produced for this assessment.")

    export_left, export_right = st.columns(2)
    with export_left:
        st.download_button(
            "⬇ Download Redacted Assessment Report",
            data=json.dumps(sanitized_export(record), indent=2),
            file_name=f"{record['assessment_id']}_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with export_right:
        if record.get("replay"):
            st.download_button(
                "⬇ Download Reproducibility Package",
                data=json.dumps(record["replay"], indent=2),
                file_name=f"{record['assessment_id']}_replay.json",
                mime="application/json",
                use_container_width=True,
            )


# ============================================================
# Settings page
# ============================================================

def settings_page():
    st.title("Settings")
    st.markdown(
        '<div class="sm-subtitle">Application configuration. Values reflect the actual current state of this prototype.</div>',
        unsafe_allow_html=True,
    )
    demo_banner()

    settings = load_settings()

    st.subheader("Platform Information")
    i1, i2 = st.columns(2)
    with i1:
        st.markdown(f"**Application name:** {settings.get('app_name', 'SecMate')}")
        st.markdown(f"**Execution mode:** {settings.get('execution_mode', 'Simulation / Demo')}")
    with i2:
        st.markdown(f"**Storage type:** {settings.get('storage_type', 'SQLite')}")
        st.markdown(f"**Authentication mode:** {settings.get('authentication_mode', 'Demo login')}")

    st.markdown('<hr class="sm-divider"/>', unsafe_allow_html=True)
    st.subheader("Assessment Workflows")
    for wf in settings.get("workflows", []):
        st.markdown(f"**{wf.get('name')}** — {wf.get('description')}")

    st.markdown('<hr class="sm-divider"/>', unsafe_allow_html=True)
    st.subheader("Default Assessment Configuration")
    st.caption("These defaults pre-fill the New Assessment form and are saved to `config/settings.yaml`.")

    with st.form("settings_form"):
        default_target = st.text_input("Default target", value=settings.get("default_target", "NovaMind AI"))
        default_workflow = st.selectbox(
            "Default workflow", engine.ALL_WORKFLOWS,
            index=engine.ALL_WORKFLOWS.index(settings.get("default_workflow"))
            if settings.get("default_workflow") in engine.ALL_WORKFLOWS else 2,
        )
        default_intensity = st.select_slider(
            "Default intensity", options=["Basic", "Standard", "Advanced"],
            value=settings.get("default_intensity", "Standard"),
        )
        save = st.form_submit_button("Save Settings")

    if save:
        settings["default_target"] = default_target
        settings["default_workflow"] = default_workflow
        settings["default_intensity"] = default_intensity
        try:
            save_settings(settings)
            st.success("Settings saved to config/settings.yaml.")
        except OSError as e:
            st.error(f"Could not save settings: {e}")


# ============================================================
# Main
# ============================================================

def main():
    init_state()
    if not st.session_state.logged_in:
        login_page()
        return

    load_css()
    if not ensure_db():
        return

    sidebar()

    page = st.session_state.page
    if page == "Dashboard":
        dashboard_page()
    elif page == "New Assessment":
        assessment_operations_page()
    elif page == "Assessment History":
        render_history_tab()
    elif page == "VAPT Findings":
        vapt_findings_page()
    elif page == "Attack Relationships":
        attack_relationships_page()
    elif page == "Reports":
        reports_page()
    elif page == "Settings":
        settings_page()
    else:
        dashboard_page()


if __name__ == "__main__":
    main()
