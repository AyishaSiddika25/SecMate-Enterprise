import re
import unittest
from pathlib import Path


INDEX_HTML = (Path(__file__).resolve().parents[1] / "index.html").read_text(encoding="utf-8")


class TestIndexUi(unittest.TestCase):
    def test_workspace_modules_are_present(self):
        for page in (
            "overview",
            "engagements",
            "onboard",
            "live",
            "findings",
            "paths",
            "reports",
            "governance",
        ):
            self.assertIn(f'data-page="{page}"', INDEX_HTML)

    def test_interactive_flows_are_wired(self):
        for element_id in (
            "login-form",
            "onboarding-form",
            "assessment-form",
            "finding-search",
            "severity-filter",
            "posture-card-body",
            "outcome-card-body",
            "finding-detail",
            "finding-detail-body",
            "presentation-mode",
            "presentation-overlay",
            "paths-card-body",
            "comparison-panel",
            "compare-baseline",
            "compare-candidate",
            "run-comparison",
            "export-report",
        ):
            self.assertIn(f'id="{element_id}"', INDEX_HTML)

    def test_assessment_form_posts_to_relative_api_route(self):
        self.assertIn('fetch("/api"', INDEX_HTML)

    def test_assessment_options_match_engine_contract(self):
        for workflow in (
            "Red Team-Blue Team Assessment",
            "VAPT Security Analysis",
            "Combined Security Assessment",
        ):
            self.assertRegex(
                INDEX_HTML,
                rf'<option(?:\s+[^>]*)?>{re.escape(workflow)}</option>',
            )

        for intensity in ("Basic", "Standard", "Advanced"):
            self.assertRegex(
                INDEX_HTML,
                rf'<option(?:\s+[^>]*)?>{re.escape(intensity)}</option>',
            )

    def test_element_ids_are_unique(self):
        ids = re.findall(r'\bid="([^"]+)"', INDEX_HTML)
        self.assertEqual(len(ids), len(set(ids)))

    def test_sidebar_uses_requested_profile_name(self):
        self.assertIn("SecMate<br>Ayisha Siddika", INDEX_HTML)
        self.assertNotIn("Security Operator", INDEX_HTML)
        self.assertNotIn("Sree S.", INDEX_HTML)
        self.assertNotIn('class="avatar">SS<', INDEX_HTML)

    def test_sidebar_typography_is_readable(self):
        self.assertRegex(INDEX_HTML, r":root\s*\{[^}]*font-size:\s*17px")
        self.assertRegex(INDEX_HTML, r"\.app-shell\s*\{[^}]*grid-template-columns:\s*264px")
        self.assertRegex(INDEX_HTML, r"\.nav-label\s*\{[^}]*font-size:\s*var\(--font-meta\)")
        self.assertRegex(INDEX_HTML, r"\.nav-item\s*\{[^}]*font-size:\s*1rem")
        self.assertRegex(INDEX_HTML, r"\.nav-count\s*\{[^}]*font-size:\s*var\(--font-label\)")
        self.assertRegex(INDEX_HTML, r"\.operator strong\s*\{[^}]*font-size:\s*\.9rem")

    def test_workspace_typography_is_readable(self):
        for selector, size in (
            ("page-heading h1", "var(--font-page-title)"),
            ("page-heading p", "var(--font-body)"),
            ("metric-label", "var(--font-caption)"),
            ("card-head h2", "var(--font-section-title)"),
            ("legend-row", "var(--font-label)"),
            ("row-title", "var(--font-body)"),
            ("row-meta", "var(--font-meta)"),
            ("app-table", "var(--font-label)"),
            ("form-grid label", "var(--font-label)"),
        ):
            with self.subTest(selector=selector):
                self.assertRegex(
                    INDEX_HTML,
                    rf"\.{re.escape(selector)}\s*\{{[^}}]*font-size:\s*{re.escape(size)}",
                )

    def test_dark_theme_readability_tokens_are_applied(self):
        for token in (
            "--workspace-bg",
            "--surface",
            "--surface-input",
            "--text-secondary",
            "--text-subtle",
            "--text-disabled",
            "--critical",
            "--warning",
            "--success",
            "--leading-body",
        ):
            self.assertIn(token, INDEX_HTML)
        self.assertIn("background: var(--surface);", INDEX_HTML)
        self.assertIn("color: var(--text-secondary);", INDEX_HTML)
        self.assertIn("border: 1px solid currentColor", INDEX_HTML)

    def test_readability_layout_has_responsive_guards(self):
        self.assertIn("@media (max-width: 1120px)", INDEX_HTML)
        self.assertIn("@media (max-width: 900px)", INDEX_HTML)
        self.assertIn("@media (max-width: 560px)", INDEX_HTML)
        self.assertRegex(
            INDEX_HTML,
            r"@media \(max-width: 1120px\)[\s\S]*?\.metric-grid\s*\{\s*grid-template-columns:\s*repeat\(2, 1fr\)",
        )
        self.assertIn(".table-wrap { overflow-x: auto; }", INDEX_HTML)
        self.assertIn(".app-topbar { justify-content: flex-start;", INDEX_HTML)

    def test_original_dashboard_content_is_preserved(self):
        for expected_value in (
            "Project Nightfall",
            "SQL injection in reporting endpoint",
            "Kerberoastable service account",
            "Domain Admin",
            "84<small>%</small>",
        ):
            self.assertIn(expected_value, INDEX_HTML)

    def test_real_assessment_enhancements_reuse_existing_dashboard(self):
        for field in ("posture", "outcome_matrix", "correlated_findings", "progress"):
            self.assertIn(field, INDEX_HTML)
        self.assertIn("renderAssessmentIntelligence(output)", INDEX_HTML)
        self.assertIn("data-finding-index", INDEX_HTML)

    def test_unique_analysis_features_are_wired(self):
        self.assertIn("Attack vs Defense Replay", INDEX_HTML)
        self.assertIn('action: "compare"', INDEX_HTML)
        self.assertIn("secmate.assessmentHistory.v1", INDEX_HTML)
        self.assertIn("openPresentation", INDEX_HTML)
        self.assertIn("redactForStorage", INDEX_HTML)

    def test_deepteam_demo_controls_and_api_action_are_wired(self):
        for element_id in (
            "deepteam-enabled",
            "deepteam-settings",
            "deepteam-status",
            "deepteam-target-mode",
            "deepteam-endpoint-field",
            "deepteam-target-endpoint",
        ):
            self.assertIn(f'id="{element_id}"', INDEX_HTML)
        self.assertIn('action = "deepteam_assess"', INDEX_HTML)
        self.assertIn('action: "deepteam_status"', INDEX_HTML)
        self.assertIn('name="deepteamVulnerability"', INDEX_HTML)
        self.assertIn('name="deepteamAttack"', INDEX_HTML)
        self.assertIn("Target endpoint / target URL", INDEX_HTML)
        self.assertIn("Target API endpoint URL", INDEX_HTML)
        self.assertIn("payload.deepteam.target_endpoint", INDEX_HTML)

    def test_agent_output_is_human_readable_instead_of_raw_json(self):
        self.assertIn('<div id="result" aria-live="polite">', INDEX_HTML)
        self.assertNotIn('<pre id="result"', INDEX_HTML)
        self.assertIn("function renderAgentOutput(record)", INDEX_HTML)
        self.assertIn("Security test results", INDEX_HTML)
        self.assertIn("Assessment progress", INDEX_HTML)
        self.assertNotIn("JSON.stringify(output, null, 2)", INDEX_HTML)


if __name__ == "__main__":
    unittest.main()
