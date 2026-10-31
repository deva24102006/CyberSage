"""
Cyber Mistake Detector - Deployment & Production WSGI Test Suite.
Verifies that all deployment configurations, WSGI entrypoints,
Procfile, requirements, and cloud simulation modes execute flawlessly.
"""

import os
import unittest
from unittest.mock import patch


class TestDeployment(unittest.TestCase):
    """Verifies production deployment configuration and stability."""

    def test_wsgi_app_importable(self):
        """The wsgi module must expose a valid Flask application instance."""
        from wsgi import app
        self.assertIsNotNone(app)
        self.assertEqual(app.name, "app")

    def test_requirements_contains_production_servers(self):
        """Requirements must specify WSGI servers for Linux (gunicorn) and Windows (waitress)."""
        root_dir = os.path.dirname(os.path.dirname(__file__))
        req_path = os.path.join(root_dir, "requirements.txt")
        self.assertTrue(os.path.exists(req_path))
        with open(req_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Flask", content)
        self.assertIn("gunicorn", content)
        self.assertIn("waitress", content)

    def test_procfile_exists_and_configured(self):
        """Procfile must exist with valid Gunicorn web process definition."""
        root_dir = os.path.dirname(os.path.dirname(__file__))
        procfile_path = os.path.join(root_dir, "Procfile")
        self.assertTrue(os.path.exists(procfile_path))
        with open(procfile_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        self.assertTrue(content.startswith("web: gunicorn wsgi:app"))

    def test_render_yaml_exists(self):
        """render.yaml blueprint must exist for 1-click cloud deployment."""
        root_dir = os.path.dirname(os.path.dirname(__file__))
        render_path = os.path.join(root_dir, "render.yaml")
        self.assertTrue(os.path.exists(render_path))
        with open(render_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("gunicorn wsgi:app", content)

    def test_dockerfile_and_dockerignore_exist(self):
        """Dockerfile and .dockerignore must exist and be well-formed."""
        root_dir = os.path.dirname(os.path.dirname(__file__))
        dockerfile = os.path.join(root_dir, "Dockerfile")
        dockerignore = os.path.join(root_dir, ".dockerignore")
        self.assertTrue(os.path.exists(dockerfile))
        self.assertTrue(os.path.exists(dockerignore))

    def test_cloud_sandbox_simulated_scan_execution(self):
        """Simulated non-Windows cloud deployment executes deep scan with zero error."""
        import scanner
        with patch("platform.system", return_value="Linux"):
            report = scanner.scan_system(mode="deep")
            self.assertIsNotNone(report)
            self.assertTrue(report.get("is_simulated"))
            self.assertEqual(len(report.get("results", [])), 12)
            self.assertIsNotNone(report.get("hygiene_percentage"))

    def test_ml_warmup_latency_is_minimal(self):
        """ML inference on preloaded models executes in under 200 milliseconds."""
        import time
        from ml_engine import load_ml_models, predict_endpoint_risk
        load_ml_models()
        start = time.perf_counter()
        prediction = predict_endpoint_risk([])
        duration = time.perf_counter() - start
        self.assertIn("risk_level", prediction)
        self.assertLess(duration, 0.20, f"ML inference took too long: {duration:.4f}s")


if __name__ == "__main__":
    unittest.main()
