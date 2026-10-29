"""
Unit tests for CyberSage AI Machine Learning Model & Prediction Engine.
"""

import os
import unittest
from ml_engine import extract_features_from_findings, predict_endpoint_risk


class TestMLEngine(unittest.TestCase):
    def test_extract_features_all_safe(self):
        """Clean endpoint findings produce all safe (1.0) feature vector."""
        findings = [
            {"name": "Windows Firewall Profiles", "status": "SAFE", "details": "All active"},
            {"name": "Microsoft Defender Real-Time Protection", "status": "SAFE", "details": "Active"},
            {"name": "Threat Definitions", "status": "SAFE", "details": "Updated 1 days ago"},
            {"name": "Windows Update", "status": "SAFE", "details": "Running"},
            {"name": "User Account Control", "status": "SAFE", "details": "EnableLUA is 1"},
            {"name": "Guest Account", "status": "SAFE", "details": "Disabled"},
            {"name": "SMBv1", "status": "SAFE", "details": "Disabled"},
            {"name": "Remote Desktop", "status": "SAFE", "details": "NLA active"},
            {"name": "Anonymous SAM", "status": "SAFE", "details": "Restricted"},
            {"name": "PUA", "status": "SAFE", "details": "Active"},
            {"name": "Controlled Folder Access", "status": "SAFE", "details": "Active"},
            {"name": "Script Block Logging", "status": "SAFE", "details": "Active"},
        ]
        features = extract_features_from_findings(findings)
        self.assertEqual(len(features), 12)
        # All binary features should be 1.0, sig_freshness should be 1.0
        self.assertEqual(features[0], 1.0) # firewall
        self.assertEqual(features[6], 1.0) # smb1
        self.assertEqual(features[10], 1.0) # cfa

    def test_extract_features_with_vulnerabilities(self):
        """Vulnerable controls produce 0.0 in corresponding feature slots."""
        findings = [
            {"name": "Windows Firewall Profiles", "status": "WARNING", "details": "Disabled"},
            {"name": "SMBv1 Legacy Protocol Exposure", "status": "WARNING", "details": "Enabled"},
            {"name": "Microsoft Defender Controlled Folder Access (Ransomware Guard)", "status": "WARNING", "details": "Disabled"},
        ]
        features = extract_features_from_findings(findings)
        self.assertEqual(features[0], 0.0) # firewall failing
        self.assertEqual(features[6], 0.0) # smb1 failing
        self.assertEqual(features[10], 0.0) # cfa failing

    def test_predict_endpoint_risk_low(self):
        """Hardened system produces LOW risk and high confidence."""
        findings = [
            {"name": "Windows Firewall Profiles", "status": "SAFE", "details": "All active"},
            {"name": "Microsoft Defender Real-Time Protection", "status": "SAFE", "details": "Active"},
            {"name": "Threat Definitions", "status": "SAFE", "details": "Updated 1 days ago"},
            {"name": "SMBv1", "status": "SAFE", "details": "Disabled"},
            {"name": "Controlled Folder Access", "status": "SAFE", "details": "Active"},
            {"name": "Script Block Logging", "status": "SAFE", "details": "Active"},
        ]
        res = predict_endpoint_risk(findings)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLess(res["breach_probability_pct"], 35.0)
        self.assertGreaterEqual(res["model_accuracy_pct"], 90.0)

    def test_predict_endpoint_risk_elevated(self):
        """System with severe vulnerabilities produces elevated breach probability."""
        findings = [
            {"name": "SMBv1 Legacy Protocol Exposure", "status": "WARNING", "details": "Enabled"},
            {"name": "Microsoft Defender Controlled Folder Access (Ransomware Guard)", "status": "WARNING", "details": "Disabled"},
            {"name": "Remote Desktop & NLA", "status": "WARNING", "details": "No NLA"},
            {"name": "Script Block Logging", "status": "WARNING", "details": "Disabled"},
        ]
        res = predict_endpoint_risk(findings)
        self.assertIn(res["risk_level"], ("MEDIUM", "CRITICAL"))
        self.assertGreaterEqual(res["breach_probability_pct"], 40.0)
        self.assertGreater(len(res["vulnerability_drivers"]), 0)

    def test_model_metadata_file_exists_and_valid(self):
        """Model metadata file exists and contains valid metrics."""
        import json
        meta_path = os.path.join(os.path.dirname(__file__), "..", "models", "model_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["total_samples"], 5000)
        self.assertGreaterEqual(data["test_accuracy_pct"], 90.0)


if __name__ == "__main__":
    unittest.main()
