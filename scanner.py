"""
CyberSage Windows Security Scanner & Live Probe Engine.

Safely evaluates Windows security configurations and deeper vulnerability
parameters using read-only PowerShell queries.
Supports:
- Live on-demand Windows inspections with evidence attribution
- Single-control re-verification (preventing false remediation claims)
- Telemetry validation and schema checking
- Demonstration sample mode for non-Windows cloud deployments
"""

import json
import logging
import os
import platform
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from recommendations import get_recommendation
from scoring import calculate_audit_score

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


def get_system_metadata() -> Dict[str, Any]:
    """Captures runtime environment and host identity parameters."""
    return {
        "hostname": platform.node() or "Unknown Host",
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "is_windows": platform.system() == "Windows",
    }


# ==============================================================================
# Security Check Probes (Read-Only)
# ==============================================================================

def check_firewall(runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell) -> Dict[str, Any]:
    """Checks Windows Firewall profiles (Domain, Private, Public)."""
    control_id = "firewall_profiles"
    name = "Windows Firewall Profiles"
    category = "Core System Defenses"
    checked_at = _now_iso()
    evidence_source = "Windows Defender Firewall Cmdlets (Get-NetFirewallProfile)"
    scope_limitations = "Verifies profile enablement. Does not inspect application bypass rules or packet filters."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "Firewall configuration query is only applicable to Windows operating systems.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not retrieve firewall profiles. Access may be restricted (Exit: {proc.returncode}).",
                "severity": "Medium",
                "observed_value": proc.stderr.strip() or "Empty stdout",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        data = json.loads(proc.stdout.strip())
        profiles = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if not profiles:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "No firewall profiles returned by operating system query.",
                "severity": "Medium",
                "observed_value": "Empty profile list",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
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
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": f"Firewall disabled on profiles: {', '.join(disabled_profiles)}. Active on: {', '.join(enabled_profiles) or 'None'}.",
                "severity": "High",
                "observed_value": f"Disabled: {disabled_profiles}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "SAFE",
            "details": f"All network profiles ({', '.join(enabled_profiles)}) have Windows Firewall enabled.",
            "severity": "Low",
            "observed_value": f"Enabled: {enabled_profiles}",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "Firewall status query timed out after 10 seconds.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying firewall status: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_defender_status(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Checks Microsoft Defender Real-Time Protection and Signature Freshness."""
    rt_id = "defender_realtime"
    rt_name = "Microsoft Defender Real-Time Protection"
    sig_id = "threat_signatures"
    sig_name = "Defender Signature Freshness"
    category = "Core System Defenses"
    checked_at = _now_iso()
    evidence_source = "Microsoft Defender Antivirus WMI / Cmdlets (Get-MpComputerStatus)"
    scope_limitations = "Verifies Defender engine state. Does not guarantee absence of zero-day threats or dormant malware."

    if platform.system() != "Windows":
        not_supported = {
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "Microsoft Defender query is only applicable to Windows operating systems.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": rt_id, "name": rt_name, **not_supported},
            {"control_id": sig_id, "name": sig_name, **not_supported},
        )

    cmd = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureVersion | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Defender status could not be read. A 3rd-party antivirus may be active or Defender management is restricted.",
                "severity": "Medium",
                "observed_value": proc.stderr.strip() or "Empty response",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
            return (
                {"control_id": rt_id, "name": rt_name, **unknown_res},
                {"control_id": sig_id, "name": sig_name, **unknown_res},
            )

        data = json.loads(proc.stdout.strip())
        if not isinstance(data, dict):
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Unexpected data format received from Defender query.",
                "severity": "Medium",
                "observed_value": str(data),
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
            return (
                {"control_id": rt_id, "name": rt_name, **unknown_res},
                {"control_id": sig_id, "name": sig_name, **unknown_res},
            )

        rt_enabled = bool(data.get("RealTimeProtectionEnabled"))
        am_service = bool(data.get("AMServiceEnabled"))

        if rt_enabled and am_service:
            rt_result = {
                "control_id": rt_id,
                "name": rt_name,
                "category": category,
                "status": "SAFE",
                "details": "Microsoft Defender Antivirus service and real-time monitoring are actively running.",
                "severity": "Low",
                "observed_value": f"RealTimeProtectionEnabled: True, AMServiceEnabled: True",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            rt_result = {
                "control_id": rt_id,
                "name": rt_name,
                "category": category,
                "status": "WARNING",
                "details": f"Real-time protection is inactive (RealTimeProtection: {rt_enabled}, AMService: {am_service}). Verify if a third-party antivirus is managing the system.",
                "severity": "High",
                "observed_value": f"RealTimeProtectionEnabled: {rt_enabled}, AMServiceEnabled: {am_service}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        sig_age = data.get("AntivirusSignatureAge")
        sig_ver = data.get("AntivirusSignatureVersion", "Unknown")
        if sig_age is None or not isinstance(sig_age, (int, float)):
            sig_result = {
                "control_id": sig_id,
                "name": sig_name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Antivirus signature age could not be determined.",
                "severity": "Low",
                "observed_value": f"Version: {sig_ver}, Age: None",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif sig_age <= 7:
            sig_result = {
                "control_id": sig_id,
                "name": sig_name,
                "category": category,
                "status": "SAFE",
                "details": f"Antivirus signatures are fresh (updated {int(sig_age)} day{'s' if int(sig_age) != 1 else ''} ago, version: {sig_ver}).",
                "severity": "Low",
                "observed_value": f"Age: {int(sig_age)} days, Version: {sig_ver}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            sig_result = {
                "control_id": sig_id,
                "name": sig_name,
                "category": category,
                "status": "WARNING",
                "details": f"Antivirus signatures are {int(sig_age)} days old (exceeds recommended 7-day threshold, version: {sig_ver}).",
                "severity": "Medium",
                "observed_value": f"Age: {int(sig_age)} days (Stale)",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        return rt_result, sig_result

    except subprocess.TimeoutExpired:
        timeout_res = {
            "category": category,
            "status": "TIMEOUT",
            "details": "Microsoft Defender query timed out after 10 seconds.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": rt_id, "name": rt_name, **timeout_res},
            {"control_id": sig_id, "name": sig_name, **timeout_res},
        )
    except Exception as exc:
        err_res = {
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Microsoft Defender: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": rt_id, "name": rt_name, **err_res},
            {"control_id": sig_id, "name": sig_name, **err_res},
        )


def check_windows_update(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks Windows Update service startup configuration (wuauserv)."""
    control_id = "windows_update"
    name = "Windows Update Service"
    category = "Core System Defenses"
    checked_at = _now_iso()
    evidence_source = "Windows Service Control Manager (wuauserv)"
    scope_limitations = "Verifies update service configuration. Does not inspect pending reboots or missing patch KB numbers."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "Windows Update service is only applicable to Windows operating systems.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
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
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not determine Windows Update service status.",
                "severity": "Medium",
                "observed_value": "Empty service response",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        if start_type_val.lower() == "disabled":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": f"Windows Update service startup is set to Disabled (Status: {status_val}). System cannot receive automated security patches.",
                "severity": "Medium",
                "observed_value": f"Startup: Disabled, Status: {status_val}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "SAFE",
            "details": f"Windows Update service is operational (Startup type: {start_type_val}, Current status: {status_val}).",
            "severity": "Low",
            "observed_value": f"Startup: {start_type_val}, Status: {status_val}",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "Windows Update service query timed out.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Windows Update service: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_uac(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks User Account Control (UAC) policy (EnableLUA)."""
    control_id = "uac_policy"
    name = "User Account Control (UAC)"
    category = "Core System Defenses"
    checked_at = _now_iso()
    evidence_source = "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"
    scope_limitations = "Verifies UAC LUA elevation architecture. Does not inspect specific prompt behavior thresholds (ConsentPromptBehaviorAdmin)."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "UAC policy query is only applicable to Windows operating systems.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output == "1":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "User Account Control is enabled (EnableLUA is active), enforcing elevation prompts.",
                "severity": "Low",
                "observed_value": "EnableLUA: 1",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif output == "0":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "User Account Control is turned off (EnableLUA is 0). Programs can silently execute elevated without prompts.",
                "severity": "High",
                "observed_value": "EnableLUA: 0",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not read system UAC registry policy (Output: {output or 'None'}).",
                "severity": "Medium",
                "observed_value": output or "No output",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "UAC policy check timed out.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying UAC policy: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_guest_account(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks whether the local built-in Guest user account is enabled or disabled."""
    control_id = "guest_account"
    name = "Built-in Guest Account"
    category = "Core System Defenses"
    checked_at = _now_iso()
    evidence_source = "Local Security Authority / SAM (Get-LocalUser Guest)"
    scope_limitations = "Verifies built-in Guest account status. Does not audit custom local accounts or password strengths."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "Local user account query is only applicable to Windows operating systems.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip().lower()

        if output == "false":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "The built-in Guest account is disabled, mitigating unauthorized local logins.",
                "severity": "Low",
                "observed_value": "Enabled: False",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif output == "true":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "The built-in Guest account is active. Anyone with access to the machine may log in without dedicated credentials.",
                "severity": "Medium",
                "observed_value": "Enabled: True",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not determine local Guest account status.",
                "severity": "Low",
                "observed_value": output or "No output",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "Guest account query timed out.",
            "severity": "Low",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Guest account: {exc}",
            "severity": "Low",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_smb1_protocol(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks if legacy SMBv1 protocol is enabled (EternalBlue / WannaCry exploit vector)."""
    control_id = "smb1_protocol"
    name = "SMBv1 Legacy Protocol Exposure"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()
    evidence_source = "SMB Server Configuration (Get-SmbServerConfiguration.EnableSMB1Protocol)"
    scope_limitations = "Verifies SMBv1 server configuration. Does not inspect active SMBv2/v3 signing or client outbound connections."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "SMB protocol query is only applicable to Windows.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip().lower()

        if output == "false":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "Legacy SMBv1 file-sharing protocol is disabled on this system.",
                "severity": "Low",
                "observed_value": "EnableSMB1Protocol: False",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif output == "true":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "SMBv1 protocol is currently ENABLED. This exposes the system to remote execution and worm vulnerabilities (MS17-010 / WannaCry).",
                "severity": "High",
                "observed_value": "EnableSMB1Protocol: True",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine SMBv1 configuration (Output: {output or 'None'}).",
                "severity": "Medium",
                "observed_value": output or "No output",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "SMBv1 configuration query timed out.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying SMBv1 protocol: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_rdp_nla_exposure(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks Remote Desktop exposure and Network Level Authentication (NLA) enforcement."""
    control_id = "rdp_nla"
    name = "Remote Desktop (RDP) & Network Level Authentication"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()
    evidence_source = "Terminal Server Registry (fDenyTSConnections & UserAuthentication)"
    scope_limitations = "Verifies RDP listener and NLA policy. Does not inspect firewall port 3389 inbound filters or router port-forwarding."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "RDP configuration check is only applicable to Windows.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "@{ fDenyTS = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections; NLA = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication } | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Unable to read Remote Desktop configuration from system registry.",
                "severity": "Medium",
                "observed_value": proc.stderr.strip() or "Empty response",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        data = json.loads(proc.stdout.strip())
        f_deny = data.get("fDenyTS")
        nla = data.get("NLA")

        # fDenyTSConnections == 1 means RDP is disabled (denied)
        if f_deny == 1:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "Remote Desktop incoming connections are disabled (fDenyTSConnections is active), eliminating external RDP attack surface.",
                "severity": "Low",
                "observed_value": "fDenyTSConnections: 1 (RDP Disabled)",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif f_deny == 0:
            if nla == 1:
                return {
                    "control_id": control_id,
                    "name": name,
                    "category": category,
                    "status": "SAFE",
                    "details": "Remote Desktop is enabled, but Network Level Authentication (NLA) is strictly required before connection establishment.",
                    "severity": "Low",
                    "observed_value": "fDenyTSConnections: 0, UserAuthentication: 1 (NLA Required)",
                    "evidence_source": evidence_source,
                    "scope_limitations": scope_limitations,
                    "checked_at": checked_at,
                }
            else:
                return {
                    "control_id": control_id,
                    "name": name,
                    "category": category,
                    "status": "WARNING",
                    "details": "Remote Desktop is enabled WITHOUT Network Level Authentication (NLA). External connections can reach the login interface unauthenticated.",
                    "severity": "High",
                    "observed_value": "fDenyTSConnections: 0, UserAuthentication: 0 (No NLA)",
                    "evidence_source": evidence_source,
                    "scope_limitations": scope_limitations,
                    "checked_at": checked_at,
                }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not determine Remote Desktop connection policy.",
                "severity": "Medium",
                "observed_value": str(data),
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "RDP policy query timed out.",
            "severity": "Medium",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying RDP/NLA configuration: {exc}",
            "severity": "Medium",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_anonymous_enumeration(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks LSA RestrictAnonymous setting (preventing anonymous SAM account and share enumeration)."""
    control_id = "restrict_anonymous"
    name = "Anonymous Network Reconnaissance Exposure"
    category = "Exploit Surface & Legacy Protocols"
    checked_at = _now_iso()
    evidence_source = "LSA Registry Policy (HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous)"
    scope_limitations = "Verifies anonymous SAM policy. Does not restrict authenticated domain account discovery."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "LSA policy query is only applicable to Windows.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).RestrictAnonymous"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output in ("1", "2"):
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": f"Anonymous enumeration of SAM accounts and shares is restricted (RestrictAnonymous is {output}).",
                "severity": "Low",
                "observed_value": f"RestrictAnonymous: {output}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        elif output == "0":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "Anonymous enumeration is permitted (RestrictAnonymous is 0). Unauthenticated users on the local network can query usernames and shares.",
                "severity": "Medium",
                "observed_value": "RestrictAnonymous: 0",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "UNKNOWN",
                "details": f"Could not determine LSA RestrictAnonymous policy (Output: {output or 'None'}).",
                "severity": "Low",
                "observed_value": output or "No output",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "Anonymous enumeration query timed out.",
            "severity": "Low",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying anonymous enumeration policy: {exc}",
            "severity": "Low",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


def check_defender_advanced_features(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Queries advanced Defender protections: PUA Protection and Controlled Folder Access (Ransomware Guard)."""
    pua_id = "pua_protection"
    pua_name = "Potentially Unwanted Application (PUA) Protection"
    cfa_id = "controlled_folder_access"
    cfa_name = "Defender Controlled Folder Access (Ransomware Guard)"
    category = "Ransomware & Threat Hardening"
    checked_at = _now_iso()
    evidence_source = "Defender Exploit Guard Cmdlets (Get-MpPreference)"
    scope_limitations = "Verifies Defender preference flags. Does not test kernel filter drivers or simulate live file encryption."

    if platform.system() != "Windows":
        not_supp = {
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "Defender Exploit Guard queries are only applicable to Windows.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": pua_id, "name": pua_name, **not_supp},
            {"control_id": cfa_id, "name": cfa_name, **not_supp},
        )

    cmd = "Get-MpPreference | Select-Object PUAProtection, EnableControlledFolderAccess | ConvertTo-Json -Compress"
    try:
        proc = runner(cmd, 10)
        if proc.returncode != 0 or not proc.stdout.strip():
            unknown_res = {
                "category": category,
                "status": "UNKNOWN",
                "details": "Could not query Defender advanced preferences.",
                "severity": "Low",
                "observed_value": proc.stderr.strip() or "Empty response",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
            return (
                {"control_id": pua_id, "name": pua_name, **unknown_res},
                {"control_id": cfa_id, "name": cfa_name, **unknown_res},
            )

        data = json.loads(proc.stdout.strip())
        pua_val = data.get("PUAProtection")
        cfa_val = data.get("EnableControlledFolderAccess")

        # PUA: 1 = Enabled, 2 = AuditMode, 0 = Disabled
        if pua_val in (1, 2):
            pua_res = {
                "control_id": pua_id,
                "name": pua_name,
                "category": category,
                "status": "SAFE",
                "details": f"Defender PUA protection is active (Mode: {pua_val}), blocking aggressive adware and bundled miners.",
                "severity": "Low",
                "observed_value": f"PUAProtection: {pua_val}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            pua_res = {
                "control_id": pua_id,
                "name": pua_name,
                "category": category,
                "status": "WARNING",
                "details": "Defender PUA protection is disabled. Bundled adware, miners, and low-reputation toolbars are not proactively blocked.",
                "severity": "Low",
                "observed_value": f"PUAProtection: {pua_val or 0}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        # CFA: 1 = Enabled, 2 = AuditMode, 0 = Disabled
        if cfa_val in (1, 2):
            cfa_res = {
                "control_id": cfa_id,
                "name": cfa_name,
                "category": category,
                "status": "SAFE",
                "details": f"Controlled Folder Access is active (Mode: {cfa_val}), shielding user folders from unauthorized ransomware encryption.",
                "severity": "Low",
                "observed_value": f"EnableControlledFolderAccess: {cfa_val}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            cfa_res = {
                "control_id": cfa_id,
                "name": cfa_name,
                "category": category,
                "status": "WARNING",
                "details": "Controlled Folder Access is disabled. Documents, Desktop, and Pictures folders lack anti-ransomware write locking.",
                "severity": "Medium",
                "observed_value": f"EnableControlledFolderAccess: {cfa_val or 0}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

        return pua_res, cfa_res

    except subprocess.TimeoutExpired:
        timeout_res = {
            "category": category,
            "status": "TIMEOUT",
            "details": "Defender advanced features query timed out.",
            "severity": "Low",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": pua_id, "name": pua_name, **timeout_res},
            {"control_id": cfa_id, "name": cfa_name, **timeout_res},
        )
    except Exception as exc:
        err_res = {
            "category": category,
            "status": "ERROR",
            "details": f"Error querying Defender preferences: {exc}",
            "severity": "Low",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
        return (
            {"control_id": pua_id, "name": pua_name, **err_res},
            {"control_id": cfa_id, "name": cfa_name, **err_res},
        )


def check_script_block_logging(
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Dict[str, Any]:
    """Checks PowerShell Script Block Logging policy (Event ID 4104)."""
    control_id = "script_block_logging"
    name = "PowerShell Script Block Logging (Forensic Auditing)"
    category = "Ransomware & Threat Hardening"
    checked_at = _now_iso()
    evidence_source = "Group Policy Registry (HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging)"
    scope_limitations = "Verifies script block logging policy. Does not inspect transcription logging or event log buffer retention sizes."

    if platform.system() != "Windows":
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "NOT_APPLICABLE",
            "details": "PowerShell Script Block Logging policy is only applicable to Windows.",
            "severity": "Low",
            "observed_value": "Non-Windows OS",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }

    cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging"
    try:
        proc = runner(cmd, 10)
        output = proc.stdout.strip()

        if output == "1":
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "SAFE",
                "details": "PowerShell Script Block Logging is enabled, recording full de-obfuscated script code to Event Log ID 4104.",
                "severity": "Low",
                "observed_value": "EnableScriptBlockLogging: 1",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }
        else:
            return {
                "control_id": control_id,
                "name": name,
                "category": category,
                "status": "WARNING",
                "details": "PowerShell Script Block Logging is not enabled. Fileless scripts and living-off-the-land malware can execute in memory without leaving detailed command traces.",
                "severity": "Medium",
                "observed_value": f"EnableScriptBlockLogging: {output or 'Not Configured'}",
                "evidence_source": evidence_source,
                "scope_limitations": scope_limitations,
                "checked_at": checked_at,
            }

    except subprocess.TimeoutExpired:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "TIMEOUT",
            "details": "Script block logging query timed out.",
            "severity": "Low",
            "observed_value": "Execution timeout",
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "control_id": control_id,
            "name": name,
            "category": category,
            "status": "ERROR",
            "details": f"Error querying script block logging policy: {exc}",
            "severity": "Low",
            "observed_value": str(exc),
            "evidence_source": evidence_source,
            "scope_limitations": scope_limitations,
            "checked_at": checked_at,
        }


# Mapping of control IDs to dedicated probe functions for single-control re-verification
CONTROL_PROBES: Dict[str, Callable[..., Any]] = {
    "firewall_profiles": check_firewall,
    "defender_realtime": lambda r: check_defender_status(r)[0],
    "threat_signatures": lambda r: check_defender_status(r)[1],
    "windows_update": check_windows_update,
    "uac_policy": check_uac,
    "guest_account": check_guest_account,
    "smb1_protocol": check_smb1_protocol,
    "rdp_nla": check_rdp_nla_exposure,
    "restrict_anonymous": check_anonymous_enumeration,
    "pua_protection": lambda r: check_defender_advanced_features(r)[0],
    "controlled_folder_access": lambda r: check_defender_advanced_features(r)[1],
    "script_block_logging": check_script_block_logging,
}


def verify_single_control(
    control_id: str,
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell
) -> Optional[Dict[str, Any]]:
    """
    Executes a fresh, read-only verification probe for a specific security control.
    Prevents false remediation claims by inspecting live system configuration.

    Args:
        control_id: Identifier of the control to verify.
        runner: Subprocess execution function.

    Returns:
        Fresh finding dictionary with updated recommendation, or None if probe unknown.
    """
    probe_fn = CONTROL_PROBES.get(control_id)
    if not probe_fn:
        return None

    try:
        raw_finding = probe_fn(runner)
        return get_recommendation(raw_finding)
    except Exception as exc:
        logger.exception("Error executing single-control probe for %s: %s", control_id, exc)
        return {
            "control_id": control_id,
            "status": "ERROR",
            "details": f"Verification probe execution failed: {exc}",
            "checked_at": _now_iso()
        }


# ==============================================================================
# Main Orchestration Engine & Demonstration Data
# ==============================================================================

def generate_demo_sample_audit(mode: str = "deep") -> Dict[str, Any]:
    """
    Generates a demonstration sample audit when running in a non-Windows cloud
    sandbox (such as Linux on Vercel) where physical Windows inspection is impossible.
    Clearly labeled as demonstration data so users are never misled.
    """
    checked_at = _now_iso()
    raw_findings: List[Dict[str, Any]] = [
        {
            "control_id": "firewall_profiles",
            "name": "Windows Firewall Profiles",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: All network profiles (Domain, Private, Public) have Windows Firewall enabled.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
        {
            "control_id": "defender_realtime",
            "name": "Microsoft Defender Real-Time Protection",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: Microsoft Defender Antivirus real-time monitoring is active.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
        {
            "control_id": "threat_signatures",
            "name": "Defender Signature Freshness",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: Threat definitions updated within the last 24 hours.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
        {
            "control_id": "windows_update",
            "name": "Windows Update Service",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: Windows Update service (wuauserv) is configured for automatic retrieval.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
        {
            "control_id": "uac_policy",
            "name": "User Account Control (UAC)",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: User Account Control elevation prompts (EnableLUA) are enabled.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
        {
            "control_id": "guest_account",
            "name": "Built-in Guest Account",
            "category": "Core System Defenses",
            "status": "SAFE",
            "details": "Sample: The default built-in local Guest account is disabled.",
            "severity": "Low",
            "observed_value": "Sample Baseline",
            "evidence_source": "Demo Profile Simulation",
            "scope_limitations": "Demonstration data only.",
            "checked_at": checked_at,
        },
    ]

    is_deep = mode.lower() in ("deep", "hard", "comprehensive")
    if is_deep:
        raw_findings.extend([
            {
                "control_id": "smb1_protocol",
                "name": "SMBv1 Legacy Protocol Exposure",
                "category": "Exploit Surface & Legacy Protocols",
                "status": "WARNING",
                "details": "Sample Finding: Legacy SMBv1 protocol is enabled, exposing the host to WannaCry (MS17-010).",
                "severity": "High",
                "observed_value": "EnableSMB1Protocol: True (Sample)",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
            {
                "control_id": "rdp_nla",
                "name": "Remote Desktop (RDP) & Network Level Authentication",
                "category": "Exploit Surface & Legacy Protocols",
                "status": "SAFE",
                "details": "Sample: Remote Desktop connections require Network Level Authentication (NLA).",
                "severity": "Low",
                "observed_value": "Sample Baseline",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
            {
                "control_id": "restrict_anonymous",
                "name": "Anonymous Network Reconnaissance Exposure",
                "category": "Exploit Surface & Legacy Protocols",
                "status": "SAFE",
                "details": "Sample: Anonymous SAM account and share enumeration is restricted.",
                "severity": "Low",
                "observed_value": "Sample Baseline",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
            {
                "control_id": "controlled_folder_access",
                "name": "Defender Controlled Folder Access (Ransomware Guard)",
                "category": "Ransomware & Threat Hardening",
                "status": "WARNING",
                "details": "Sample Finding: Controlled Folder Access is disabled; user folders lack anti-ransomware protection.",
                "severity": "Medium",
                "observed_value": "EnableControlledFolderAccess: 0 (Sample)",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
            {
                "control_id": "pua_protection",
                "name": "Potentially Unwanted Application (PUA) Protection",
                "category": "Ransomware & Threat Hardening",
                "status": "WARNING",
                "details": "Sample Finding: Potentially Unwanted Application (PUA) blocking is disabled.",
                "severity": "Low",
                "observed_value": "PUAProtection: 0 (Sample)",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
            {
                "control_id": "script_block_logging",
                "name": "PowerShell Script Block Logging (Forensic Auditing)",
                "category": "Ransomware & Threat Hardening",
                "status": "WARNING",
                "details": "Sample Finding: PowerShell Script Block Logging is not enabled for Event ID 4104 auditing.",
                "severity": "Medium",
                "observed_value": "EnableScriptBlockLogging: 0 (Sample)",
                "evidence_source": "Demo Profile Simulation",
                "scope_limitations": "Demonstration data only.",
                "checked_at": checked_at,
            },
        ])
        scan_mode_label = "Hard System Vulnerability Audit (12 Checks)"
    else:
        scan_mode_label = "Quick Baseline Audit (6 Checks)"

    findings = [get_recommendation(item) for item in raw_findings]
    score_data = calculate_audit_score(findings, scan_mode=mode)

    return {
        "scan_id": str(uuid.uuid4()),
        "scan_mode": mode.lower(),
        "scan_mode_label": scan_mode_label,
        "scan_source": "demo_sample",
        "target_host": "Cloud Sandbox (Sample Preset)",
        "results": findings,
        "hygiene_percentage": score_data["score"],
        "score_label": score_data["score_label"],
        "score_status": score_data["score_status"],
        "total_checks": score_data["total_checks"],
        "applicable_count": score_data["applicable_count"],
        "safe_count": score_data["safe_count"],
        "warning_count": score_data["warning_count"],
        "unknown_count": score_data["unknown_count"],
        "not_applicable_count": score_data["not_applicable_count"],
        "high_severity_count": score_data["high_severity_count"],
        "is_complete": score_data["is_complete"],
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "coverage_note": score_data["summary_note"],
        "disclaimer": (
            "Demonstration Notice: This sample report illustrates defensive configuration parameters in a cloud environment. "
            "To audit your physical Windows PC, run CyberSage_Scanner on your endpoint and upload the telemetry file."
        ),
        "is_simulated": True,
        "environment_label": "Cloud Serverless Demo Environment (Synthetic Assessment - Not Your Physical PC)",
    }


def scan_system(
    mode: str = "deep",
    runner: Callable[[str, int], subprocess.CompletedProcess] = run_powershell,
    force_simulation: bool = False,
) -> Dict[str, Any]:
    """
    Orchestrates the Windows security audit.

    - On Windows: Performs real, read-only local system inspection with evidence.
    - On Non-Windows: Explicitly returns a demonstration sample clearly labeled as demo data.

    Args:
        mode: "quick" for baseline 6 checks, or "deep" for comprehensive 12 checks.
        runner: Subprocess execution function.
        force_simulation: Force demonstration mode regardless of host OS.
    """
    sys_meta = get_system_metadata()
    is_windows = sys_meta["is_windows"]

    if (not is_windows and runner == run_powershell) or force_simulation or mode.lower() in ("demo", "simulation"):
        logger.info("Host is %s; generating clearly labeled demonstration sample.", sys_meta["os_name"])
        return generate_demo_sample_audit(mode=mode)

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

    findings = [get_recommendation(item) for item in raw_findings]
    score_data = calculate_audit_score(findings, scan_mode=mode)

    return {
        "scan_id": str(uuid.uuid4()),
        "scan_mode": mode.lower(),
        "scan_mode_label": scan_mode_label,
        "scan_source": "local_host",
        "target_host": f"{sys_meta['hostname']} ({sys_meta['os_name']} {sys_meta['os_release']})",
        "results": findings,
        "hygiene_percentage": score_data["score"],
        "score_label": score_data["score_label"],
        "score_status": score_data["score_status"],
        "total_checks": score_data["total_checks"],
        "applicable_count": score_data["applicable_count"],
        "safe_count": score_data["safe_count"],
        "warning_count": score_data["warning_count"],
        "unknown_count": score_data["unknown_count"],
        "not_applicable_count": score_data["not_applicable_count"],
        "high_severity_count": score_data["high_severity_count"],
        "is_complete": score_data["is_complete"],
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "coverage_note": score_data["summary_note"],
        "disclaimer": (
            "Educational Notice: This scanner checks specific Windows configuration parameters and defensive controls. "
            "A high hygiene score indicates solid defensive baseline adherence, but does NOT guarantee complete security "
            "or the absence of advanced malware or zero-day exploits."
        ),
        "is_simulated": False,
        "environment_label": f"Local Windows Host: {sys_meta['hostname']}",
    }
