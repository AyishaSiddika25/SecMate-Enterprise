import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestVercelConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(
            (PROJECT_ROOT / "vercel.json").read_text(encoding="utf-8")
        )

    def test_frontend_and_api_have_separate_builds(self):
        builds = {
            build["src"]: build["use"] for build in self.config.get("builds", [])
        }
        self.assertEqual(builds.get("index.html"), "@vercel/static")
        self.assertEqual(builds.get("api/index.py"), "@vercel/python")

    def test_python_function_excludes_local_only_files(self):
        api_build = next(
            build for build in self.config["builds"] if build["src"] == "api/index.py"
        )
        exclude_files = api_build["config"]["excludeFiles"]
        for pattern in (".npm-cache/**", ".vercel-global/**", "app/**", "tests/**"):
            self.assertIn(pattern, exclude_files)

    def test_api_route_precedes_frontend_root(self):
        routes = self.config["routes"]
        self.assertEqual(routes[0], {"src": "/api/?", "dest": "/api/index.py"})
        self.assertEqual(routes[1], {"src": "/", "dest": "/index.html"})

    def test_root_never_points_to_python_handler(self):
        root_route = next(route for route in self.config["routes"] if route["src"] == "/")
        self.assertEqual(root_route["dest"], "/index.html")
        self.assertNotEqual(root_route["dest"], "/api/index.py")


if __name__ == "__main__":
    unittest.main()
