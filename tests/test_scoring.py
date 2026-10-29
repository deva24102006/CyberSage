"""
Unit tests for CyberSage Authoritative Scoring Engine.
"""

import unittest
from scoring import calculate_audit_score


class TestScoring(unittest.TestCase):
    def test_all_safe_controls_yields_100(self):
        findings = [
            {"control_id": f"c_{i}", "status": "SAFE", "severity": "Medium"}
            for i in range(6)
        ]
        result = calculate_audit_score(findings, scan_mode="quick")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["safe_count"], 6)
        self.assertEqual(result["warning_count"], 0)
        self.assertEqual(result["score_status"], "VALID")
        self.assertIn("Baseline Audit Score", result["score_label"])

    def test_all_warning_controls_yields_0(self):
        findings = [
            {"control_id": f"c_{i}", "status": "WARNING", "severity": "High"}
            for i in range(12)
        ]
        result = calculate_audit_score(findings, scan_mode="deep")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["safe_count"], 0)
        self.assertEqual(result["warning_count"], 12)
        self.assertEqual(result["high_severity_count"], 12)
        self.assertIn("Hard Audit Score", result["score_label"])

    def test_not_applicable_excluded_from_denominator(self):
        """Controls marked NOT_APPLICABLE must not dilute or penalize the score denominator."""
        findings = [
            {"control_id": "c_1", "status": "SAFE", "severity": "Low"},
            {"control_id": "c_2", "status": "SAFE", "severity": "Low"},
            {"control_id": "c_3", "status": "NOT_APPLICABLE", "severity": "Info"},
        ]
        result = calculate_audit_score(findings, scan_mode="quick")
        # 2 safe out of 2 applicable = 100%
        self.assertEqual(result["total_checks"], 3)
        self.assertEqual(result["applicable_count"], 2)
        self.assertEqual(result["not_applicable_count"], 1)
        self.assertEqual(result["score"], 100)

    def test_unknown_and_error_do_not_count_as_safe(self):
        """Unverified, unknown, or error checks must NEVER silently count as safe."""
        findings = [
            {"control_id": "c_1", "status": "SAFE", "severity": "Low"},
            {"control_id": "c_2", "status": "WARNING", "severity": "High"},
            {"control_id": "c_3", "status": "UNKNOWN", "severity": "Medium"},
        ]
        result = calculate_audit_score(findings, scan_mode="quick")
        # 1 safe out of 3 applicable controls = 33%
        self.assertEqual(result["safe_count"], 1)
        self.assertEqual(result["warning_count"], 1)
        self.assertEqual(result["unknown_count"], 1)
        self.assertEqual(result["score"], 33)

    def test_incomplete_scan_withholds_score_when_too_many_unknowns(self):
        """If >33% of controls fail to evaluate (e.g. permission denied), score is withheld (None)."""
        findings = [
            {"control_id": "c_1", "status": "SAFE", "severity": "Low"},
            {"control_id": "c_2", "status": "UNKNOWN", "severity": "Medium"},
            {"control_id": "c_3", "status": "ERROR", "severity": "High"},
        ]
        # 2 of 3 are unknown/error = 66% unverified (> 33% threshold)
        result = calculate_audit_score(findings, scan_mode="quick")
        self.assertIsNone(result["score"])
        self.assertEqual(result["score_status"], "INCOMPLETE_SCAN")
        self.assertFalse(result["is_complete"])
        self.assertIn("Score is withheld", result["summary_note"])

    def test_empty_findings_returns_none(self):
        result = calculate_audit_score([], scan_mode="quick")
        self.assertIsNone(result["score"])
        self.assertEqual(result["score_status"], "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
