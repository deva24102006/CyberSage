"""
Integration tests for Flask application in Cyber Mistake Detector.
Tests HTTP routes, HTML rendering, static file serving, and error handling.
"""

import unittest
from unittest.mock import patch

import app as flask_app_module
from app import app


class TestApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        flask_app_module.latest_report = None

    def test_home_route_status_and_content(self):
        """Home page must return HTTP 200 and contain expected title and structure."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Cyber Mistake Detector", html)
        self.assertIn("Run Hard System Scan", html)
        self.assertIn("SMBv1 Protocol Exposure", html)
        self.assertTrue(len(html) > 500)

    def test_results_redirects_before_scan(self):
        """Accessing /results before any scan must redirect to home (HTTP 302)."""
        response = self.client.get("/results")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/"))

    def test_scan_and_results_flow(self):
        """POST /scan should run scanner and redirect to /results, which renders HTTP 200."""
        mock_report = {
            "results": [
                {
                    "name": "SMBv1 Legacy Protocol Exposure",
                    "category": "Exploit Surface & Legacy Protocols",
                    "status": "SAFE",
                    "details": "SMBv1 protocol is disabled.",
                    "severity": "Low",
                    "checked_at": "2026-10-28T00:00:00Z",
                    "recommendation": {
                        "summary": "SMBv1 legacy protocol is disabled.",
                        "what_checked": "SMBv1 state.",
                        "what_it_means": "Incoming SMBv1 traffic blocked.",
                        "why_it_matters": "Neutralizes EternalBlue/WannaCry vector.",
                        "next_steps": ["Keep SMBv1 disabled."],
                    },
                }
            ],
            "scan_mode": "deep",
            "scan_mode_label": "Hard System Vulnerability Audit (12 Checks)",
            "total_checks": 1,
            "safe_count": 1,
            "warning_count": 0,
            "high_severity_count": 0,
            "unknown_count": 0,
            "evaluated_count": 1,
            "hygiene_percentage": 100,
            "scanned_at": "2026-10-28 00:00:00 UTC",
            "coverage_note": "1 of 1 passed.",
            "disclaimer": "Educational notice.",
        }

        with patch("app.scan_system", return_value=mock_report):
            post_response = self.client.post("/scan", data={"mode": "deep"})
            self.assertEqual(post_response.status_code, 302)
            self.assertTrue(post_response.location.endswith("/results"))

            results_response = self.client.get("/results")
            self.assertEqual(results_response.status_code, 200)
            html = results_response.get_data(as_text=True)
            self.assertIn("Audit Report", html)
            self.assertIn("Hard System Vulnerability Audit", html)
            self.assertIn("SMBv1 Legacy Protocol Exposure", html)
            self.assertIn("SAFE", html)
            self.assertIn("100%", html)
            self.assertIn("Rerun Hard Scan", html)

    def test_scan_graceful_error_handling(self):
        """If scanner encounters an unexpected exception, app does not crash."""
        with patch("app.scan_system", side_effect=RuntimeError("Subprocess failed")):
            post_response = self.client.post("/scan")
            self.assertEqual(post_response.status_code, 302)

            results_response = self.client.get("/results")
            self.assertEqual(results_response.status_code, 200)
            html = results_response.get_data(as_text=True)
            self.assertIn("Scanner Engine", html)
            self.assertIn("ERROR", html)

    def test_static_css_served(self):
        """CSS stylesheet must be accessible and non-empty."""
        response = self.client.get("/static/css/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cyber Mistake Detector", response.get_data(as_text=True))

    def test_static_js_served(self):
        """JavaScript client script must be accessible and non-empty."""
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cyber Mistake Detector", response.get_data(as_text=True))

    def test_custom_404_handler(self):
        """Requesting an invalid route returns HTTP 404 with custom error page."""
        response = self.client.get("/nonexistent-page-url")
        self.assertEqual(response.status_code, 404)
        html = response.get_data(as_text=True)
        self.assertIn("Page Not Found", html)

    def test_upload_valid_report(self):
        """Uploading a valid JSON audit report renders results."""
        import io
        import json
        payload = {
            "results": [
                {
                    "name": "Windows Firewall Profiles",
                    "status": "SAFE",
                    "details": "All profiles active.",
                    "severity": "Low",
                    "category": "Core System Defenses",
                    "checked_at": "2026-10-28T00:00:00Z"
                }
            ],
            "total_checks": 1,
            "safe_count": 1,
            "warning_count": 0,
            "high_severity_count": 0,
            "unknown_count": 0,
            "evaluated_count": 1,
            "hygiene_percentage": 100,
            "scan_mode": "deep",
            "scan_mode_label": "Local Physical Windows PC",
            "scanned_at": "2026-10-28 00:00:00 UTC",
            "coverage_note": "1 of 1 passed."
        }
        data = {
            "report_file": (io.BytesIO(json.dumps(payload).encode("utf-8")), "audit_report.json")
        }
        res = self.client.post("/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 302)
        results_page = self.client.get("/results")
        self.assertEqual(results_page.status_code, 200)
        self.assertIn("Windows Firewall Profiles", results_page.get_data(as_text=True))

    def test_download_auditor(self):
        """Downloading auditor script returns 200 with attachment."""
        res = self.client.get("/download-auditor")
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment", res.headers.get("Content-Disposition", ""))


if __name__ == "__main__":
    unittest.main()
