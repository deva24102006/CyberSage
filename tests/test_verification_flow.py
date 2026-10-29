"""
Integration & unit tests for Bug 2 & Bug 4 verification flow:
- Authoritative backend probe execution via POST /api/verify-control.
- Proof that clicking 'Verify & Mark Remediated' without fixing does NOT increase score.
- Proof that successfully fixed settings update score authoritatively.
- Immutable verification audit logging in SQLite.
"""

import json
import unittest
import uuid
from unittest.mock import patch

from app import app
from storage import get_scan, get_verifications_for_scan, init_db, save_scan


class TestVerificationFlow(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()
        self.session_id = str(uuid.uuid4())

        self.initial_report = {
            "scan_id": str(uuid.uuid4()),
            "scan_mode": "deep",
            "scan_source": "local_host",
            "target_host": "TEST-ENDPOINT-01",
            "scanned_at": "2026-10-29 10:00:00 UTC",
            "hygiene_percentage": 50,
            "score_label": "Hard System Vulnerability Hygiene",
            "score_status": "COMPLETE",
            "total_checks": 2,
            "applicable_count": 2,
            "safe_count": 1,
            "warning_count": 1,
            "unknown_count": 0,
            "not_applicable_count": 0,
            "high_severity_count": 1,
            "is_complete": True,
            "results": [
                {
                    "control_id": "firewall_profiles",
                    "name": "Windows Defender Firewall Profiles",
                    "status": "SAFE",
                    "severity": "High",
                    "details": "All profiles enabled.",
                },
                {
                    "control_id": "smbv1_protocol",
                    "name": "SMBv1 Legacy Protocol Exposure",
                    "status": "WARNING",
                    "severity": "High",
                    "details": "SMB1Protocol is currently ENABLED.",
                },
            ],
        }

    def test_verify_missing_parameters_returns_400(self):
        with self.client.session_transaction() as sess:
            sess["session_id"] = self.session_id

        res = self.client.post("/api/verify-control", json={})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["outcome"], "INVALID_REQUEST")

    def test_verify_nonexistent_scan_returns_404(self):
        with self.client.session_transaction() as sess:
            sess["session_id"] = self.session_id

        res = self.client.post(
            "/api/verify-control",
            json={"scan_id": "nonexistent-scan-id", "control_id": "smbv1_protocol"},
        )
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["outcome"], "SCAN_NOT_FOUND")

    def test_verify_on_demo_mode_rejected(self):
        """Demo cloud sample scans cannot claim local endpoint verification."""
        demo_report = dict(self.initial_report)
        demo_report["scan_id"] = str(uuid.uuid4())
        demo_report["scan_source"] = "demo_sample"
        scan_id = save_scan(demo_report, self.session_id)

        with self.client.session_transaction() as sess:
            sess["session_id"] = self.session_id

        res = self.client.post(
            "/api/verify-control",
            json={"scan_id": scan_id, "control_id": "smbv1_protocol"},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["outcome"], "DEMO_MODE")

    @patch("app.platform.system", return_value="Windows")
    @patch("app.verify_single_control")
    def test_unfixed_vulnerability_verification_fails_and_score_cannot_increase(
        self, mock_verify, mock_platform
    ):
        """
        CRITICAL TEST FOR BUG 2:
        User clicks 'Verify & Mark Remediated' WITHOUT actually applying the fix.
        PowerShell probe finds setting is still insecure.
        Result: Status remains WARNING, score MUST NOT increase!
        """
        scan_id = save_scan(self.initial_report, self.session_id)

        # Mock probe finding SMBv1 STILL ENABLED (Unfixed)
        mock_verify.return_value = {
            "control_id": "smbv1_protocol",
            "name": "SMBv1 Legacy Protocol Exposure",
            "status": "WARNING",
            "severity": "High",
            "details": "SMB1Protocol is still ENABLED on this computer.",
            "evidence_source": "PowerShell Live Probe",
        }

        with self.client.session_transaction() as sess:
            sess["session_id"] = self.session_id

        res = self.client.post(
            "/api/verify-control",
            json={"scan_id": scan_id, "control_id": "smbv1_protocol"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Verification must report failure
        self.assertFalse(data["success"])
        self.assertEqual(data["outcome"], "STILL_FAILING")
        self.assertEqual(data["new_status"], "WARNING")
        # Authoritative score must remain 50%, NOT increase!
        self.assertEqual(data["score"], 50)

        # Stored scan in database must also retain WARNING and 50%
        stored = get_scan(scan_id)
        self.assertEqual(stored["hygiene_percentage"], 50)
        smb_finding = next(
            f for f in stored["results"] if f["control_id"] == "smbv1_protocol"
        )
        self.assertEqual(smb_finding["status"], "WARNING")

        # Audit trail must record the failed verification attempt
        logs = get_verifications_for_scan(scan_id)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["outcome"], "STILL_FAILING")
        self.assertEqual(logs[0]["previous_status"], "WARNING")
        self.assertEqual(logs[0]["new_status"], "WARNING")

    @patch("app.platform.system", return_value="Windows")
    @patch("app.verify_single_control")
    def test_fixed_vulnerability_verification_succeeds_and_score_increases(
        self, mock_verify, mock_platform
    ):
        """
        User applied fix on Windows machine.
        PowerShell probe confirms setting is now SAFE.
        Result: Status flips to SAFE, authoritative score increases to 100%.
        """
        scan_id = save_scan(self.initial_report, self.session_id)

        # Mock probe finding SMBv1 successfully DISABLED
        mock_verify.return_value = {
            "control_id": "smbv1_protocol",
            "name": "SMBv1 Legacy Protocol Exposure",
            "status": "SAFE",
            "severity": "High",
            "details": "SMB1Protocol is disabled and verified inactive.",
            "evidence_source": "PowerShell Live Probe",
        }

        with self.client.session_transaction() as sess:
            sess["session_id"] = self.session_id

        res = self.client.post(
            "/api/verify-control",
            json={"scan_id": scan_id, "control_id": "smbv1_protocol"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data["success"])
        self.assertEqual(data["outcome"], "VERIFIED_SAFE")
        self.assertEqual(data["new_status"], "SAFE")
        # Score increases from 50% (1 of 2) to 100% (2 of 2)
        self.assertEqual(data["score"], 100)
        self.assertEqual(data["safe_count"], 2)
        self.assertEqual(data["warning_count"], 0)

        # Stored scan in database must be updated
        stored = get_scan(scan_id)
        self.assertEqual(stored["hygiene_percentage"], 100)
        smb_finding = next(
            f for f in stored["results"] if f["control_id"] == "smbv1_protocol"
        )
        self.assertEqual(smb_finding["status"], "SAFE")

        # Audit trail records successful verification
        logs = get_verifications_for_scan(scan_id)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["outcome"], "VERIFIED_SAFE")
        self.assertEqual(logs[0]["previous_status"], "WARNING")
        self.assertEqual(logs[0]["new_status"], "SAFE")


if __name__ == "__main__":
    unittest.main()
