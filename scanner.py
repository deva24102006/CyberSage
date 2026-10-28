"""
Windows Security Scanner for Cyber Mistake Detector.

Safely evaluates Windows security configurations and deeper vulnerability
parameters using read-only PowerShell queries.
Supports both Quick Baseline Scans and Hard / Deep System Vulnerability Audits.
"""

import json
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from recommendations import get_recommendation

logger = logging.getLogger(__name__)


def run_powershell(command: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """
    Safely executes a read-only PowerShell command.

    Args:
        command: The PowerShell command string.
        timeout: Execution timeout in seconds.

    Returns:
        subprocess.CompletedProcess instance.
    """
    cmd_args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ]
    return subprocess.run(
        cmd_args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _now_iso() -> str:
    """Returns current UTC ISO-8601 formatted timestamp."""
    return datetime.now(timezone.utc).isoformat()


# ==============================================================================
# Core Baseline Security Checks
# ==============================================================================

def check_firewall(runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell) -> Dict[str, Any]:
    """Checks Windows Firewall profiles (Domain, Private, Public)."""
    name = "Windows Firewall Profiles"
    category = "Core System Defenses"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "Firewall configuration query is only supported on Windows operating systems.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not retrieve firewall profiles. Windows Defender Firewall cmdlets may be restricted.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        data = json.loads(proc.stdout.strip())
        profiles = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if not profiles:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "No firewall profiles were returned by the operating system query.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        disabled_profiles = []
        enabled_profiles = []
        for p in profiles:
            p_name = p.get("Name", "Unknown")
            is_enabled = bool(p.get("Enabled"))
            if is_enabled:
                enabled_profiles.append(p_name)
            else:
                disabled_profiles.append(p_name)

        if disabled_profiles:
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": f"Firewall is disabled on: {', '.join(disabled_profiles)}. Enabled on: {', '.join(enabled_profiles) if enabled_profiles else 'None'}.",
                "severity": "High",
                "checked_at": checked_at,
            }

        return {
            "name": name,
            "category": category,
            "status": "SAFE",
            "details": f"All network profiles ({', '.join(enabled_profiles)}) have Windows Firewall enabled.",
            "severity": "Low",
            "checked_at": checked_at,
        }

    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": "The firewall status query timed out after 10 seconds.",
            "severity": "Medium",
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"An error occurred while querying firewall status: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }


def check_defender_status(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Checks Microsoft Defender Real-Time Protection and Signature Freshness."""
    rt_name = "Microsoft Defender Real-Time Protection"
    sig_name = "Defender Signature Freshness"
    category = "Core System Defenses"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        not_supported = {
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "Microsoft Defender query is only supported on Windows operating systems.",
            "severity": "Info",
            "checked_at": checked_at,
        }
        return (
            {"name": rt_name, **not_supported},
            {"name": sig_name, **not_supported},
        )

    cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge | ConvertTo-Json -Compress"

    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Defender status could not be read. A third-party antivirus may be active or Defender management is restricted.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
            return (
                {"name": rt_name, **unknown_res},
                {"name": sig_name, **unknown_res},
            )

        data = json.loads(proc.stdout.strip())
        if not isinstance(data, dict):
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Unexpected data format received from Microsoft Defender query.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
            return (
                {"name": rt_name, **unknown_res},
                {"name": sig_name, **unknown_res},
            )

        rt_enabled = bool(data.get("RealTimeProtectionEnabled"))
        am_service = bool(data.get("AMServiceEnabled"))

        if rt_enabled and am_service:
            rt_result = {
                "name": rt_name,
                "category": category,
                "status": "SAFE",
                "details": "Microsoft Defender Antivirus service and real-time monitoring are actively running.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        else:
            rt_result = {
                "name": rt_name,
                "category": category,
                "status": "WARNING",
                "details": f"Real-time protection is inactive (RealTimeProtectionEnabled: {rt_enabled}, AMServiceEnabled: {am_service}). Verify if a 3rd-party antivirus is managing your PC.",
                "severity": "High",
                "checked_at": checked_at,
            }

        sig_age = data.get("AntivirusSignatureAge")
        if sig_age is None or not isinstance(sig_age, (int, float)):
            sig_result = {
                "name": sig_name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Antivirus signature age could not be determined from the system response.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif sig_age <= 7:
            sig_result = {
                "name": sig_name,
                "category": category,
                "status": "SAFE",
                "details": f"Antivirus signatures are fresh (updated {int(sig_age)} day{'s' if int(sig_age) != 1 else ''} ago).",
                "severity": "Low",
                "checked_at": checked_at,
            }
        else:
            sig_result = {
                "name": sig_name,
                "category": category,
                "status": "WARNING",
                "details": f"Antivirus signatures are {int(sig_age)} days old. Recommended threshold is within 7 days.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        return rt_result, sig_result

    except subprocess.TimeoutExpired:
        timeout_res = {
            "category": category,
            "status": "ERROR",
            "details": "The Microsoft Defender query timed out after 10 seconds.",
            "severity": "Medium",
            "checked_at": checked_at,
        }
        return (
            {"name": rt_name, **timeout_res},
            {"name": sig_name, **timeout_res},
        )
    except Exception as exc:
        err_res = {
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Microsoft Defender: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }
        return (
            {"name": rt_name, **err_res},
            {"name": sig_name, **err_res},
        )


def check_windows_update(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks Windows Update service status (wuauserv)."""
    name = "Windows Update Service"
    category = "Core System Defenses"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "Windows Update service query is only supported on Windows operating systems.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "Write-Output ('Status:' + (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status); Write-Output ('StartType:' + (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType)"
    try:
        proc = runner(cmd, 10)
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        status_val = ""
        start_type_val = ""

        for line in lines:
            if line.startswith("Status:"):
                status_val = line.split("Status:", 1)[1].strip()
            elif line.startswith("StartType:"):
                start_type_val = line.split("StartType:", 1)[1].strip()

        if not status_val and not start_type_val:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not determine Windows Update service status.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        if start_type_val.lower() == "disabled":
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": f"Windows Update service startup type is set to Disabled. Status: {status_val}.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        return {
            "name": name,
            "category": category,
            "status": "SAFE",
            "details": f"Windows Update service is enabled (Startup type: {start_type_val}, Current status: {status_val}).",
            "severity": "Low",
            "checked_at": checked_at,
        }

    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": "The Windows Update service query timed out.",
            "severity": "Medium",
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Windows Update service: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }


def check_uac(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks User Account Control (UAC) policy (EnableLUA)."""
    name = "User Account Control (UAC)"
    category = "Core System Defenses"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "UAC policy query is only supported on Windows operating systems.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output == "1":
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "User Account Control is enabled (EnableLUA is active), enforcing elevation prompts.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif output == "0":
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "User Account Control is turned off (EnableLUA is 0). Applications can run elevated without prompts.",
                "severity": "High",
                "checked_at": checked_at,
            }
        else:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not read the system UAC registry policy (Output: {output or 'None'}).",
                "severity": "Medium",
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": "UAC policy check timed out.",
            "severity": "Medium",
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying UAC policy: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }


def check_guest_account(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks whether the local built-in Guest user account is enabled or disabled."""
    name = "Built-in Guest Account"
    category = "Core System Defenses"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "Local user account query is only supported on Windows operating systems.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output.lower() == "false":
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "The built-in Guest account is disabled, mitigating unauthorized local logins.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif output.lower() == "true":
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "The built-in Guest account is enabled. Anyone with access to the machine may sign in.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
        else:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not query Guest account status.",
                "severity": "Low",
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": "Guest account query timed out.",
            "severity": "Low",
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Guest account: {exc}",
            "severity": "Low",
            "checked_at": checked_at,
        }


# ==============================================================================
# Hard Scan / Deeper System Vulnerability Audits
# ==============================================================================

def check_smb1_protocol(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """
    Checks if legacy SMBv1 protocol is enabled (EternalBlue / WannaCry exploit vector).
    """
    name = "SMBv1 Legacy Protocol Exposure"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "SMB protocol query is only supported on Windows.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip().lower()

        if output == "false":
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "Legacy SMBv1 file-sharing protocol is disabled on this system.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif output == "true":
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "SMBv1 protocol is currently ENABLED. This exposes the system to critical legacy worm and remote execution vulnerabilities (EternalBlue / MS17-010).",
                "severity": "High",
                "checked_at": checked_at,
            }
        else:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine SMBv1 configuration (Output: {output or 'None'}).",
                "severity": "Medium",
                "checked_at": checked_at,
            }

    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying SMBv1 protocol: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }


def check_rdp_nla_exposure(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """
    Checks Remote Desktop exposure and Network Level Authentication (NLA) enforcement.
    """
    name = "Remote Desktop (RDP) & Network Level Authentication"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "RDP configuration check is only supported on Windows.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "@{ fDenyTS = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections; NLA = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication } | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Unable to read Remote Desktop configuration from the system registry.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

        data = json.loads(proc.stdout.strip())
        f_deny = data.get("fDenyTS")
        nla = data.get("NLA")

        # fDenyTSConnections == 1 means RDP is disabled (denied)
        if f_deny == 1:
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "Remote Desktop incoming connections are disabled (fDenyTSConnections is active), eliminating external RDP attack surface.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif f_deny == 0:
            if nla == 1:
                return {
                    "name": name,
                    "category": category,
                    "status": "SAFE",
                    "details": "Remote Desktop is enabled, but Network Level Authentication (NLA) is strictly required before connection establishment.",
                    "severity": "Low",
                    "checked_at": checked_at,
                }
            else:
                return {
                    "name": name,
                    "category": category,
                    "status": "WARNING",
                    "details": "Remote Desktop is enabled WITHOUT Network Level Authentication (NLA). External connections can reach the login interface unauthenticated.",
                    "severity": "High",
                    "checked_at": checked_at,
                }
        else:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not determine Remote Desktop connection policy.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying RDP/NLA configuration: {exc}",
            "severity": "Medium",
            "checked_at": checked_at,
        }


def check_anonymous_enumeration(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """
    Checks LSA RestrictAnonymous setting (preventing anonymous SAM account and share enumeration).
    """
    name = "Anonymous Network Reconnaissance Exposure"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "LSA policy query is only supported on Windows.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).RestrictAnonymous"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output in ("1", "2"):
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": f"Anonymous enumeration of SAM accounts and shares is restricted (RestrictAnonymous is {output}).",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif output == "0":
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "Anonymous enumeration is permitted (RestrictAnonymous is 0). Unauthenticated users on the local network can list usernames and shares.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
        else:
            return {
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine LSA RestrictAnonymous policy (Output: {output or 'None'}).",
                "severity": "Low",
                "checked_at": checked_at,
            }

    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying anonymous enumeration policy: {exc}",
            "severity": "Low",
            "checked_at": checked_at,
        }


def check_defender_advanced_features(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Queries advanced Defender protections: PUA Protection and Controlled Folder Access (Ransomware Guard).
    Returns (pua_check, ransomware_guard_check).
    """
    pua_name = "Potentially Unwanted Application (PUA) Protection"
    cfa_name = "Defender Controlled Folder Access (Ransomware Guard)"
    category = "Ransomware & Threat Hardening"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        not_supp = {
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "Query is only supported on Windows.",
            "severity": "Info",
            "checked_at": checked_at,
        }
        return ({"name": pua_name, **not_supp}, {"name": cfa_name, **not_supp})

    cmd = "Get-MpPreference | Select-Object PUAProtection, EnableControlledFolderAccess | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Defender advanced preferences could not be read.",
                "severity": "Low",
                "checked_at": checked_at,
            }
            return ({"name": pua_name, **unknown_res}, {"name": cfa_name, **unknown_res})

        data = json.loads(proc.stdout.strip())
        pua_val = data.get("PUAProtection")
        cfa_val = data.get("EnableControlledFolderAccess")

        # PUA Check: 1 = Enabled, 2 = AuditMode
        if pua_val in (1, 2):
            pua_res = {
                "name": pua_name,
                "category": category,
                "status": "SAFE",
                "details": f"Defender PUA protection is active (Mode: {pua_val}), blocking aggressive adware and bundled miners.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif pua_val == 0:
            pua_res = {
                "name": pua_name,
                "category": category,
                "status": "WARNING",
                "details": "Defender PUA protection is turned off (0). Low-reputation adware and bundled installers will not be blocked automatically.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
        else:
            pua_res = {
                "name": pua_name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine PUA protection state ({pua_val}).",
                "severity": "Low",
                "checked_at": checked_at,
            }

        # Controlled Folder Access Check: 1 = Enabled, 2 = AuditMode
        if cfa_val in (1, 2):
            cfa_res = {
                "name": cfa_name,
                "category": category,
                "status": "SAFE",
                "details": f"Controlled Folder Access is active (Mode: {cfa_val}), shielding user folders from unauthorized ransomware encryption.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        elif cfa_val == 0:
            cfa_res = {
                "name": cfa_name,
                "category": category,
                "status": "WARNING",
                "details": "Controlled Folder Access (Ransomware Guard) is disabled (0). User documents and desktop folders are not protected from unauthorized process encryption.",
                "severity": "Medium",
                "checked_at": checked_at,
            }
        else:
            cfa_res = {
                "name": cfa_name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine Controlled Folder Access state ({cfa_val}).",
                "severity": "Low",
                "checked_at": checked_at,
            }

        return pua_res, cfa_res

    except Exception as exc:
        err_res = {
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Defender advanced features: {exc}",
            "severity": "Low",
            "checked_at": checked_at,
        }
        return ({"name": pua_name, **err_res}, {"name": cfa_name, **err_res})


def check_script_block_logging(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """
    Checks if PowerShell Script Block Logging (Event ID 4104) is enabled for forensic auditing.
    """
    name = "PowerShell Script Block Logging (Forensic Auditing)"
    category = "Ransomware & Threat Hardening"
    checked_at = _now_iso()

    if platform.system() != "Windows":
        return {
            "name": name,
            "category": category,
            "status": "NOT SUPPORTED",
            "details": "PowerShell logging policy query is only supported on Windows.",
            "severity": "Info",
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output == "1":
            return {
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "PowerShell Script Block Logging is enabled, recording full de-obfuscated script code to Event Log ID 4104.",
                "severity": "Low",
                "checked_at": checked_at,
            }
        else:
            return {
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "PowerShell Script Block Logging is not enabled. Fileless scripts and living-off-the-land malware can execute in memory without leaving detailed command traces.",
                "severity": "Medium",
                "checked_at": checked_at,
            }

    except Exception as exc:
        return {
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying script block logging policy: {exc}",
            "severity": "Low",
            "checked_at": checked_at,
        }


# ==============================================================================
# Main Orchestration Engine
# ==============================================================================

def scan_system(
    mode: str = "deep",
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """
    Runs security checks, gathers findings, generates recommendations,
    and returns a structured report with summary metrics.

    Args:
        mode: "quick" for baseline 6 checks, or "deep" / "hard" for comprehensive 12 checks.
        runner: Subprocess execution function.
    """
    raw_findings: List[Dict[str, Any]] = []

    # 1-6. Core Baseline Checks
    raw_findings.append(check_firewall(runner))
    rt_check, sig_check = check_defender_status(runner)
    raw_findings.append(rt_check)
    raw_findings.append(sig_check)
    raw_findings.append(check_windows_update(runner))
    raw_findings.append(check_uac(runner))
    raw_findings.append(check_guest_account(runner))

    # 7-12. Hard Scan / Deeper Vulnerability Audits
    if mode.lower() in ("deep", "hard", "comprehensive"):
        raw_findings.append(check_smb1_protocol(runner))
        raw_findings.append(check_rdp_nla_exposure(runner))
        raw_findings.append(check_anonymous_enumeration(runner))
        pua_check, cfa_check = check_defender_advanced_features(runner)
        raw_findings.append(pua_check)
        raw_findings.append(cfa_check)
        raw_findings.append(check_script_block_logging(runner))
        scan_mode_label = "Hard System Vulnerability Audit (12 Checks)"
    else:
        scan_mode_label = "Quick Baseline Audit (6 Checks)"

    # Enrich findings with recommendations
    findings = [get_recommendation(item) for item in raw_findings]

    # Calculate metrics
    safe_count = sum(1 for item in findings if item.get("status") == "SAFE")
    warning_count = sum(1 for item in findings if item.get("status") == "WARNING")
    unknown_count = sum(
        1 for item in findings if item.get("status") in ("UNKNOWN", "NOT SUPPORTED", "ERROR")
    )
    total_checks = len(findings)

    # High severity warnings
    high_severity_count = sum(
        1 for item in findings if item.get("status") == "WARNING" and item.get("severity") == "High"
    )

    evaluated_count = safe_count + warning_count
    if evaluated_count > 0:
        hygiene_percentage = round((safe_count / evaluated_count) * 100)
    else:
        hygiene_percentage = None

    report = {
        "results": findings,
        "scan_mode": mode.lower(),
        "scan_mode_label": scan_mode_label,
        "total_checks": total_checks,
        "safe_count": safe_count,
        "warning_count": warning_count,
        "high_severity_count": high_severity_count,
        "unknown_count": unknown_count,
        "evaluated_count": evaluated_count,
        "hygiene_percentage": hygiene_percentage,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "coverage_note": (
            f"{safe_count} of {evaluated_count} evaluated configuration parameters passed defensive best practices. "
            f"{warning_count} potential weaknesses were detected."
        ),
        "disclaimer": (
            "Educational Notice: This scanner checks specific Windows configuration parameters and defensive controls. "
            "A high hygiene score indicates solid defensive baseline adherence, but does NOT guarantee complete security "
            "or the absence of advanced malware or zero-day exploits."
        ),
    }

    return report
