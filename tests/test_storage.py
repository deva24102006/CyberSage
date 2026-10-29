"""
Unit tests for CyberSage SQLite storage and session isolation engine.
"""

import os
import unittest
import uuid
from storage import (
    db_session,
    get_latest_scan_for_session,
    get_scan,
    get_verifications_for_scan,
    init_db,
    record_verification,
    save_scan,
    update_scan,
)


class TestStorage(unittest.TestCase):
    def setUp(self):
        init_db()
        self.session_a = f"test_session_a_{uuid.uuid4()}"
        self.session_b = f"test_session_b_{uuid.uuid4()}"
        self.mock_report_a = {
            "scan_id": str(uuid.uuid4()),
            "scan_mode": "deep",
            "scan_source": "local_host",
            "target_host": "TEST-WIN-01",
            "scanned_at": "2026-10-29 10:00:00 UTC",
            "hygiene_percentage": 75,
            "score_label": "Hard System Vulnerability Hygiene",
            "score_status": "COMPLETE",
            "total_checks": 12,
            "safe_count": 9,
            "warning_count": 3,
            "unknown_count": 0,
            "not_applicable_count": 0,
            "high_severity_count": 1,
            "is_complete": True,
            "results": [
                {
                    "control_id": "smbv1_protocol",
                    "name": "SMBv1 Legacy Protocol Exposure",
                    "status": "WARNING",
                    "severity": "High",
                    "details": "SMBv1 is active.",
                }
            ],
        }

    def test_save_and_retrieve_scan(self):
        scan_id = save_scan(self.mock_report_a, self.session_a)
        retrieved = get_scan(scan_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["scan_id"], scan_id)
        self.assertEqual(retrieved["hygiene_percentage"], 75)
        self.assertEqual(retrieved["target_host"], "TEST-WIN-01")

    def test_session_isolation(self):
        """User in Session B cannot see latest scan of Session A."""
        scan_id = save_scan(self.mock_report_a, self.session_a)

        latest_a = get_latest_scan_for_session(self.session_a)
        self.assertIsNotNone(latest_a)
        self.assertEqual(latest_a["scan_id"], scan_id)

        latest_b = get_latest_scan_for_session(self.session_b)
        self.assertIsNone(latest_b)

    def test_update_scan_persists_changes(self):
        scan_id = save_scan(self.mock_report_a, self.session_a)
        retrieved = get_scan(scan_id)
        retrieved["hygiene_percentage"] = 83
        retrieved["safe_count"] = 10
        retrieved["warning_count"] = 2

        updated = update_scan(retrieved, self.session_a)
        self.assertTrue(updated)

        refreshed = get_scan(scan_id)
        self.assertEqual(refreshed["hygiene_percentage"], 83)
        self.assertEqual(refreshed["safe_count"], 10)
        self.assertEqual(refreshed["warning_count"], 2)

    def test_record_and_retrieve_verifications(self):
        scan_id = save_scan(self.mock_report_a, self.session_a)
        verif_id = record_verification(
            scan_id=scan_id,
            control_id="smbv1_protocol",
            control_name="SMBv1 Legacy Protocol Exposure",
            previous_status="WARNING",
            new_status="SAFE",
            outcome="VERIFIED_SAFE",
            details="Disable-WindowsOptionalFeature confirmed SMB1 is disabled.",
        )
        self.assertTrue(bool(verif_id))

        history = get_verifications_for_scan(scan_id)
        self.assertEqual(len(history), 1)
        record = history[0]
        self.assertEqual(record["control_id"], "smbv1_protocol")
        self.assertEqual(record["previous_status"], "WARNING")
        self.assertEqual(record["new_status"], "SAFE")
        self.assertEqual(record["outcome"], "VERIFIED_SAFE")


if __name__ == "__main__":
    unittest.main()
