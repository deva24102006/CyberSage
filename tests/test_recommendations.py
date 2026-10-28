"""
Unit tests for recommendations.py in Cyber Mistake Detector.
Tests both baseline and deep vulnerability checks.
"""

import unittest
from recommendations import get_recommendation


class TestRecommendations(unittest.TestCase):
    def test_firewall_safe_recommendation(self):
        finding = {
            "name": "Windows Firewall Profiles",
            "status": "SAFE",
            "details": "All profiles enabled."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("active across Domain, Private, and Public", rec.get("summary", ""))
        self.assertTrue(len(rec.get("next_steps", [])) > 0)
        self.assertIn("what_checked", rec)
        self.assertIn("what_it_means", rec)
        self.assertIn("why_it_matters", rec)

    def test_firewall_warning_recommendation(self):
        finding = {
            "name": "Windows Firewall Profiles",
            "status": "WARNING",
            "details": "Firewall is disabled on: Private."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("turned off", rec.get("summary", ""))
        self.assertTrue(any("Firewall & network protection" in s for s in rec.get("next_steps", [])))

    def test_smb1_warning_recommendation(self):
        finding = {
            "name": "SMBv1 Legacy Protocol Exposure",
            "status": "WARNING",
            "details": "SMBv1 is enabled."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("enabled", rec.get("summary", "").lower())
        self.assertIn("wannacry", rec.get("why_it_matters", "").lower())
        self.assertTrue(any("optionalfeatures.exe" in s for s in rec.get("next_steps", [])))

    def test_rdp_nla_warning_recommendation(self):
        finding = {
            "name": "Remote Desktop (RDP) & Network Level Authentication",
            "status": "WARNING",
            "details": "RDP enabled without NLA."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("Network Level Authentication", rec.get("summary", ""))
        self.assertTrue(any("Remote Desktop" in s for s in rec.get("next_steps", [])))

    def test_pua_protection_warning(self):
        finding = {
            "name": "Potentially Unwanted Application (PUA) Protection",
            "status": "WARNING",
            "details": "PUA protection is turned off."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("turned off", rec.get("summary", "").lower())
        self.assertTrue(any("Reputation-based protection" in s for s in rec.get("next_steps", [])))

    def test_controlled_folder_access_warning(self):
        finding = {
            "name": "Defender Controlled Folder Access (Ransomware Guard)",
            "status": "WARNING",
            "details": "Controlled folder access is disabled."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("disabled", rec.get("summary", "").lower())
        self.assertIn("ransomware", rec.get("why_it_matters", "").lower())

    def test_script_block_logging_warning(self):
        finding = {
            "name": "PowerShell Script Block Logging (Forensic Auditing)",
            "status": "WARNING",
            "details": "Script block logging not enabled."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("disabled", rec.get("summary", "").lower())
        self.assertTrue(any("gpedit.msc" in s for s in rec.get("next_steps", [])))

    def test_anonymous_recon_warning(self):
        finding = {
            "name": "Anonymous Network Reconnaissance Exposure",
            "status": "WARNING",
            "details": "RestrictAnonymous is 0."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("permitted", rec.get("summary", "").lower())
        self.assertTrue(any("secpol.msc" in s for s in rec.get("next_steps", [])))

    def test_unknown_status(self):
        finding = {
            "name": "Custom Configuration Check",
            "status": "UNKNOWN",
            "details": "Unable to determine."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("could not conclusively verify", rec.get("summary", "").lower())

    def test_not_supported_status(self):
        finding = {
            "name": "Windows Firewall Profiles",
            "status": "NOT SUPPORTED",
            "details": "Not running on Windows."
        }
        enriched = get_recommendation(finding)
        rec = enriched.get("recommendation", {})
        self.assertIn("not supported", rec.get("summary", "").lower())


if __name__ == "__main__":
    unittest.main()
