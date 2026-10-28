"""
Unit tests for scanner.py in Cyber Mistake Detector.
Tests both quick baseline and deep / hard vulnerability audits.
"""

import subprocess
import unittest
from unittest.mock import patch

from scanner import (
    check_firewall,
    check_defender_status,
    check_windows_update,
    check_uac,
    check_guest_account,
    check_smb1_protocol,
    check_rdp_nla_exposure,
    check_anonymous_enumeration,
    check_defender_advanced_features,
    check_script_block_logging,
    scan_system,
)


def mock_completed(stdout: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["powershell.exe"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class TestScanner(unittest.TestCase):
    @patch("scanner.platform.system", return_value="Windows")
    def test_firewall_all_enabled(self, _):
        json_out = '[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]'
        runner = lambda cmd, to=10: mock_completed(json_out)
        res = check_firewall(runner=runner)
        self.assertEqual(res["status"], "SAFE")
        self.assertIn("All network profiles", res["details"])

    @patch("scanner.platform.system", return_value="Windows")
    def test_firewall_private_disabled(self, _):
        json_out = '[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":0},{"Name":"Public","Enabled":1}]'
        runner = lambda cmd, to=10: mock_completed(json_out)
        res = check_firewall(runner=runner)
        self.assertEqual(res["status"], "WARNING")
        self.assertEqual(res["severity"], "High")

    @patch("scanner.platform.system", return_value="Windows")
    def test_smb1_disabled_is_safe(self, _):
        runner = lambda cmd, to=10: mock_completed("False")
        res = check_smb1_protocol(runner=runner)
        self.assertEqual(res["status"], "SAFE")
        self.assertIn("disabled", res["details"].lower())

    @patch("scanner.platform.system", return_value="Windows")
    def test_smb1_enabled_is_warning(self, _):
        runner = lambda cmd, to=10: mock_completed("True")
        res = check_smb1_protocol(runner=runner)
        self.assertEqual(res["status"], "WARNING")
        self.assertEqual(res["severity"], "High")
        self.assertIn("ENABLED", res["details"])

    @patch("scanner.platform.system", return_value="Windows")
    def test_rdp_disabled_is_safe(self, _):
        runner = lambda cmd, to=10: mock_completed('{"fDenyTS":1,"NLA":0}')
        res = check_rdp_nla_exposure(runner=runner)
        self.assertEqual(res["status"], "SAFE")
        self.assertIn("disabled", res["details"].lower())

    @patch("scanner.platform.system", return_value="Windows")
    def test_rdp_enabled_without_nla_is_warning(self, _):
        runner = lambda cmd, to=10: mock_completed('{"fDenyTS":0,"NLA":0}')
        res = check_rdp_nla_exposure(runner=runner)
        self.assertEqual(res["status"], "WARNING")
        self.assertEqual(res["severity"], "High")

    @patch("scanner.platform.system", return_value="Windows")
    def test_rdp_enabled_with_nla_is_safe(self, _):
        runner = lambda cmd, to=10: mock_completed('{"fDenyTS":0,"NLA":1}')
        res = check_rdp_nla_exposure(runner=runner)
        self.assertEqual(res["status"], "SAFE")

    @patch("scanner.platform.system", return_value="Windows")
    def test_anonymous_enumeration_restricted_is_safe(self, _):
        runner = lambda cmd, to=10: mock_completed("1")
        res = check_anonymous_enumeration(runner=runner)
        self.assertEqual(res["status"], "SAFE")

    @patch("scanner.platform.system", return_value="Windows")
    def test_anonymous_enumeration_permitted_is_warning(self, _):
        runner = lambda cmd, to=10: mock_completed("0")
        res = check_anonymous_enumeration(runner=runner)
        self.assertEqual(res["status"], "WARNING")

    @patch("scanner.platform.system", return_value="Windows")
    def test_pua_and_cfa_safe(self, _):
        runner = lambda cmd, to=10: mock_completed('{"PUAProtection":1,"EnableControlledFolderAccess":1}')
        pua, cfa = check_defender_advanced_features(runner=runner)
        self.assertEqual(pua["status"], "SAFE")
        self.assertEqual(cfa["status"], "SAFE")

    @patch("scanner.platform.system", return_value="Windows")
    def test_pua_and_cfa_warnings(self, _):
        runner = lambda cmd, to=10: mock_completed('{"PUAProtection":0,"EnableControlledFolderAccess":0}')
        pua, cfa = check_defender_advanced_features(runner=runner)
        self.assertEqual(pua["status"], "WARNING")
        self.assertEqual(cfa["status"], "WARNING")

    @patch("scanner.platform.system", return_value="Windows")
    def test_script_block_logging_enabled_is_safe(self, _):
        runner = lambda cmd, to=10: mock_completed("1")
        res = check_script_block_logging(runner=runner)
        self.assertEqual(res["status"], "SAFE")

    @patch("scanner.platform.system", return_value="Windows")
    def test_script_block_logging_disabled_is_warning(self, _):
        runner = lambda cmd, to=10: mock_completed("")
        res = check_script_block_logging(runner=runner)
        self.assertEqual(res["status"], "WARNING")

    @patch("scanner.platform.system", return_value="Windows")
    def test_quick_scan_produces_6_checks(self, _):
        def dummy_runner(cmd, to=10):
            if "Get-NetFirewallProfile" in cmd:
                return mock_completed('[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]')
            if "Get-MpComputerStatus" in cmd:
                return mock_completed('{"AMServiceEnabled":true,"AntispywareEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":2}')
            if "wuauserv" in cmd:
                return mock_completed("Status:Running\nStartType:Manual\n")
            if "EnableLUA" in cmd:
                return mock_completed("1")
            if "Get-LocalUser" in cmd:
                return mock_completed("False")
            return mock_completed("")

        report = scan_system(mode="quick", runner=dummy_runner)
        self.assertEqual(report["total_checks"], 6)
        self.assertEqual(report["scan_mode"], "quick")
        self.assertIn("6 Checks", report["scan_mode_label"])

    @patch("scanner.platform.system", return_value="Windows")
    def test_deep_hard_scan_produces_12_checks(self, _):
        def dummy_runner(cmd, to=10):
            if "Get-NetFirewallProfile" in cmd:
                return mock_completed('[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]')
            if "Get-MpComputerStatus" in cmd:
                return mock_completed('{"AMServiceEnabled":true,"AntispywareEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":2}')
            if "wuauserv" in cmd:
                return mock_completed("Status:Running\nStartType:Manual\n")
            if "EnableLUA" in cmd:
                return mock_completed("1")
            if "Get-LocalUser" in cmd:
                return mock_completed("False")
            if "EnableSMB1Protocol" in cmd:
                return mock_completed("False")
            if "fDenyTS" in cmd:
                return mock_completed('{"fDenyTS":1,"NLA":0}')
            if "RestrictAnonymous" in cmd:
                return mock_completed("1")
            if "PUAProtection" in cmd:
                return mock_completed('{"PUAProtection":1,"EnableControlledFolderAccess":1}')
            if "ScriptBlockLogging" in cmd:
                return mock_completed("1")
            return mock_completed("")

        report = scan_system(mode="deep", runner=dummy_runner)
        self.assertEqual(report["total_checks"], 12)
        self.assertEqual(report["safe_count"], 12)
        self.assertEqual(report["warning_count"], 0)
        self.assertEqual(report["hygiene_percentage"], 100)
        self.assertIn("12 Checks", report["scan_mode_label"])


if __name__ == "__main__":
    unittest.main()
