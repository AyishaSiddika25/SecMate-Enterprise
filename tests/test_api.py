import unittest

from api.index import process_assessment, process_request
from core.engine import ALL_WORKFLOWS, INTENSITY_CONFIG


class TestApi(unittest.TestCase):
    def test_process_assessment(self):
        result = process_assessment({
            "target": "demo-app",
            "workflow": "VAPT Security Analysis",
            "intensity": "Basic",
            "evidence": "possible SQL injection",
        })
        self.assertEqual(result["target"], "demo-app")
        self.assertEqual(result["status"], "Completed")
        self.assertTrue(result["ok"])
        self.assertIn("posture", result)

    def test_target_is_required(self):
        with self.assertRaisesRegex(ValueError, "Target is required"):
            process_assessment({
                "target": "",
                "workflow": "VAPT Security Analysis",
                "intensity": "Basic",
            })

    def test_unknown_workflow_is_rejected(self):
        with self.assertRaisesRegex(Exception, "Unknown workflow"):
            process_assessment({
                "target": "demo-app",
                "workflow": "Unknown",
                "intensity": "Basic",
            })

    def test_all_supported_workflow_and_intensity_combinations(self):
        for workflow in ALL_WORKFLOWS:
            for intensity in INTENSITY_CONFIG:
                with self.subTest(workflow=workflow, intensity=intensity):
                    result = process_assessment({
                        "target": "demo-app",
                        "workflow": workflow,
                        "intensity": intensity,
                        "evidence": "possible SQL injection",
                    })
                    self.assertEqual(result["assessment_type"], workflow)
                    self.assertEqual(result["intensity"], intensity)
                    self.assertEqual(result["status"], "Completed")

    def test_compare_action(self):
        baseline = process_assessment({
            "target": "demo-app",
            "workflow": "VAPT Security Analysis",
            "intensity": "Basic",
            "evidence": "stack trace",
        })
        candidate = process_assessment({
            "target": "demo-app",
            "workflow": "VAPT Security Analysis",
            "intensity": "Basic",
            "evidence": "",
        })
        output = process_request({"action": "compare", "baseline": baseline, "candidate": candidate})
        self.assertTrue(output["ok"])
        self.assertEqual(output["action"], "compare")
        self.assertTrue(output["comparison"]["resolved_findings"])


if __name__ == "__main__":
    unittest.main()
