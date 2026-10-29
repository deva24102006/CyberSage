"""
CyberSage Recommendations Engine.

Translates raw security check findings into structured, professional
educational recommendations that explain:
1. What was checked (Verification scope & limits)
2. What the result means (Technical significance)
3. Threat Vector & Exploit Impact (MITRE ATT&CK / CVE mapping)
4. GUI Remediation Steps (Safer Windows Settings interface instructions)
5. Diagnostic / Read-Only Command (Safe inspection)
6. Remediation Command (Elevated terminal syntax)
7. Operational Impact & Restart Requirement
8. Verification Command (Validating the fix post-application)
"""

from typing import Any, Dict


def get_recommendation(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a security check result with structured educational guidance.

    Args:
        result: A dictionary containing at least 'name', 'status', and optionally 'control_id'.

    Returns:
        The updated dictionary with a structured 'recommendation' dictionary.
    """
    name = result.get("name", "")
    status = str(result.get("status", "UNKNOWN")).upper()
    details = result.get("details", "")
    control_id = result.get("control_id", "")

    recommendation = _build_recommendation(name, status, details, control_id)

    enriched = dict(result)
    enriched["recommendation"] = recommendation
    return enriched


def _build_recommendation(name: str, status: str, details: str, control_id: str = "") -> Dict[str, Any]:
    """Generates structured recommendation based on check name, status, and control_id."""

    # 1. Windows Firewall
    if "Firewall" in name or control_id == "firewall_profiles":
        if status == "SAFE":
            return {
                "summary": "Windows Firewall is active across Domain, Private, and Public network profiles.",
                "what_checked": "Checked whether Windows Defender Firewall is enabled for Domain, Private, and Public network connections.",
                "what_it_means": "Your computer actively inspects and filters inbound network traffic across all network types.",
                "why_it_matters": "Firewalls block unauthorized incoming connections, network scanners, and automated worms from probing open ports.",
                "reference": "CIS Microsoft Windows Benchmark Section 9.1-9.3 | MITRE ATT&CK T1562.004",
                "diagnostic_command": "netsh advfirewall show allprofiles",
                "remediation_command": "netsh advfirewall set allprofiles state on",
                "verification_command": "netsh advfirewall show allprofiles state",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Inbound connection requests to background services are filtered. Outbound web traffic is unaffected.",
                "cli_command": "netsh advfirewall set allprofiles state on",
                "next_steps": [
                    "No action required. Firewall profiles are operational.",
                    "Verify settings anytime: Start > Settings > Privacy & security > Windows Security > Firewall & network protection."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "One or more Windows Firewall profiles are turned off.",
                "what_checked": "Checked Windows Defender Firewall profiles (Domain, Private, and Public).",
                "what_it_means": "At least one network profile is unprotected, allowing unfiltered inbound traffic.",
                "why_it_matters": "Disabling a firewall profile allows unauthorized devices on the local network or internet to probe background services.",
                "reference": "CIS Microsoft Windows Benchmark Section 9.1-9.3 | MITRE ATT&CK T1562.004",
                "diagnostic_command": "netsh advfirewall show allprofiles",
                "remediation_command": "netsh advfirewall set allprofiles state on",
                "verification_command": "netsh advfirewall show allprofiles state",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Restores inbound filtering across all profiles. Outbound connections remain unaffected.",
                "cli_command": "netsh advfirewall set allprofiles state on",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Firewall & network protection'.",
                    "Click on each profile showing 'Firewall is off' and switch the toggle to 'On'.",
                    "Or open an Administrator terminal and run: netsh advfirewall set allprofiles state on"
                ]
            }

    # 2. Microsoft Defender Real-Time Protection
    if "Defender Real-Time" in name or control_id == "defender_realtime":
        if status == "SAFE":
            return {
                "summary": "Microsoft Defender real-time protection is active.",
                "what_checked": "Checked whether the Microsoft Defender Antivirus service and real-time process monitoring are running.",
                "what_it_means": "Active processes, files being opened or downloaded, and system memory are continuously monitored for known threats.",
                "why_it_matters": "Real-time protection detects and halts malware, spyware, and ransomware before they execute or encrypt personal documents.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9 | MITRE ATT&CK T1562.001",
                "diagnostic_command": "powershell \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled\"",
                "remediation_command": "powershell \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                "verification_command": "powershell \"(Get-MpComputerStatus).RealTimeProtectionEnabled\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Enables real-time file and memory scanning. If third-party antivirus is installed, Defender yields control.",
                "cli_command": "powershell \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                "next_steps": [
                    "No action required. Real-time protection is active.",
                    "Avoid disabling protection when prompted by untrusted third-party installers."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Real-time antivirus protection is currently turned off or inactive.",
                "what_checked": "Checked Microsoft Defender real-time protection status.",
                "what_it_means": "The system is not actively scanning files or background programs as they are accessed or downloaded.",
                "why_it_matters": "Without real-time scanning, malicious files can enter and execute without immediate interception.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9 | MITRE ATT&CK T1562.001",
                "diagnostic_command": "powershell \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled\"",
                "remediation_command": "powershell \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                "verification_command": "powershell \"(Get-MpComputerStatus).RealTimeProtectionEnabled\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Restores automated background scanning. Note: If third-party antivirus is active, verify that tool instead.",
                "cli_command": "powershell \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Virus & threat protection', then 'Manage settings' under Virus & threat protection settings.",
                    "Switch 'Real-time protection' to 'On'.",
                    "Note: If using third-party antivirus (Bitdefender, CrowdStrike, Malwarebytes), ensure its shields are active."
                ]
            }

    # 3. Defender Signature Freshness
    if "Signature" in name or "Definition" in name or control_id == "threat_signatures":
        if status == "SAFE":
            return {
                "summary": "Antivirus threat definitions are up to date (updated within the past 7 days).",
                "what_checked": "Checked the age of Microsoft Defender security intelligence definition files.",
                "what_it_means": "Your antivirus has recent intelligence on known malware families, trojans, and malicious payloads.",
                "why_it_matters": "Fresh signatures ensure your system recognizes the newest threats.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.23",
                "diagnostic_command": "powershell \"(Get-MpComputerStatus).AntivirusSignatureAge\"",
                "remediation_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "verification_command": "powershell \"(Get-MpComputerStatus).AntivirusSignatureAge\"",
                "requires_elevation": False,
                "requires_restart": False,
                "potential_impact": "Downloads latest definition package from Microsoft Cloud (minor network traffic).",
                "cli_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "next_steps": [
                    "No action required. Threat definitions are fresh.",
                    "Windows Update automatically retrieves definition packages periodically."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Antivirus threat definitions are outdated (older than 7 days).",
                "what_checked": "Checked the age of Microsoft Defender security intelligence definition files.",
                "what_it_means": "The definition database has not been refreshed recently; recent threat variants may not be detected.",
                "why_it_matters": "Outdated signatures create an intelligence gap where newer threats can slip past signature-based detection.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.23",
                "diagnostic_command": "powershell \"(Get-MpComputerStatus).AntivirusSignatureAge\"",
                "remediation_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "verification_command": "powershell \"(Get-MpComputerStatus).AntivirusSignatureAge\"",
                "requires_elevation": False,
                "requires_restart": False,
                "potential_impact": "Updates threat signatures. Safe and non-disruptive.",
                "cli_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Virus & threat protection', then 'Check for updates' under Protection updates.",
                    "Or run from terminal: \"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate"
                ]
            }

    # 4. Windows Update
    if "Windows Update" in name or control_id == "windows_update":
        if status == "SAFE":
            return {
                "summary": "Windows Update service is operational.",
                "what_checked": "Checked the Windows Update system service (wuauserv) configuration.",
                "what_it_means": "The operating system is configured to receive maintenance patches and security updates from Microsoft.",
                "why_it_matters": "Regular updates patch newly discovered security vulnerabilities in Windows components, preventing remote exploit attempts.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.10 | MITRE ATT&CK T1190",
                "diagnostic_command": "sc query wuauserv",
                "remediation_command": "sc config wuauserv start= demand & net start wuauserv",
                "verification_command": "powershell \"(Get-Service wuauserv).StartType\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Enables background retrieval of operating system quality updates.",
                "cli_command": "sc query wuauserv",
                "next_steps": [
                    "No immediate action required.",
                    "Regularly review Start > Settings > Windows Update to ensure monthly quality updates install."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Windows Update service is disabled.",
                "what_checked": "Checked the Windows Update service configuration.",
                "what_it_means": "The service responsible for retrieving security bulletins and OS updates is disabled.",
                "why_it_matters": "When updates are disabled, known security flaws remain unpatched, exposing the PC to public exploits.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.10 | MITRE ATT&CK T1190",
                "diagnostic_command": "sc query wuauserv",
                "remediation_command": "sc config wuauserv start= demand & net start wuauserv",
                "verification_command": "powershell \"(Get-Service wuauserv).StartType\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Restores Windows Update service startup from Disabled to Demand Start.",
                "cli_command": "sc config wuauserv start= demand & net start wuauserv",
                "next_steps": [
                    "Press Windows Key + R, type 'services.msc', and press Enter.",
                    "Scroll down to 'Windows Update', double-click it, change Startup type to 'Manual', and click 'Start'.",
                    "Or run from an Administrator terminal: sc config wuauserv start= demand & net start wuauserv"
                ]
            }

    # 5. User Account Control (UAC)
    if "User Account Control" in name or "UAC" in name or control_id == "uac_policy":
        if status == "SAFE":
            return {
                "summary": "User Account Control (UAC) is enabled.",
                "what_checked": "Checked the Windows elevation policy (EnableLUA).",
                "what_it_means": "Applications cannot silently obtain administrative privileges without prompting for confirmation.",
                "why_it_matters": "UAC prevents rogue scripts, malicious installers, or background software from making changes to core system files without knowledge.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.17 | MITRE ATT&CK T1548.002",
                "diagnostic_command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA",
                "remediation_command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA\"",
                "requires_elevation": True,
                "requires_restart": True,
                "potential_impact": "Enforces elevation consent prompts. A reboot is required to activate the LUA architecture if it was off.",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA",
                "next_steps": [
                    "No action required. UAC is enforcing elevation boundaries.",
                    "Read prompt titles carefully before clicking 'Yes' when an application requests administrative rights."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "User Account Control (UAC) is disabled.",
                "what_checked": "Checked the Windows elevation policy (EnableLUA).",
                "what_it_means": "Elevation prompts are turned off; programs can run with administrative privileges without asking for approval.",
                "why_it_matters": "Without UAC, any malware running in your user session can silently alter system files and install rootkits.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.17 | MITRE ATT&CK T1548.002",
                "diagnostic_command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA",
                "remediation_command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA\"",
                "requires_elevation": True,
                "requires_restart": True,
                "potential_impact": "Enables administrative prompts. Requires restarting your computer to take effect.",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Start > type 'Change User Account Control settings' and press Enter.",
                    "Drag slider to recommended default level ('Notify me only when apps try to make changes').",
                    "Click 'OK' and restart your PC.",
                    "Or run from Administrator terminal: reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f"
                ]
            }

    # 6. Built-in Guest Account
    if "Guest Account" in name or control_id == "guest_account":
        if status == "SAFE":
            return {
                "summary": "The built-in Guest account is disabled.",
                "what_checked": "Checked whether the local Windows 'Guest' user account is active.",
                "what_it_means": "Unauthenticated or casual users cannot log in to your machine without valid, assigned account credentials.",
                "why_it_matters": "Disabling unnecessary default accounts adheres to least privilege and reduces local attack surfaces.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.1.1 | MITRE ATT&CK T1078",
                "diagnostic_command": "net user Guest",
                "remediation_command": "net user Guest /active:no",
                "verification_command": "powershell \"(Get-LocalUser Guest).Enabled\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Prevents anonymous local console sign-ins.",
                "cli_command": "net user Guest",
                "next_steps": [
                    "No action required. Guest account is disabled.",
                    "Maintain individual, non-shared accounts for all system users."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "The built-in Guest account is active.",
                "what_checked": "Checked whether the local Windows 'Guest' user account is active.",
                "what_it_means": "The computer permits local sign-in using the built-in guest identity.",
                "why_it_matters": "Active guest accounts can be leveraged by unauthorized individuals with physical access to explore files.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.1.1 | MITRE ATT&CK T1078",
                "diagnostic_command": "net user Guest",
                "remediation_command": "net user Guest /active:no",
                "verification_command": "powershell \"(Get-LocalUser Guest).Enabled\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Disables the Guest account immediately without logging out active authorized users.",
                "cli_command": "net user Guest /active:no",
                "next_steps": [
                    "Open Administrator terminal and run: net user Guest /active:no",
                    "Or press Windows Key + R, type 'lusrmgr.msc' > Users > Guest > check 'Account is disabled'."
                ]
            }

    # 7. SMBv1 Legacy Protocol Exposure
    if "SMBv1" in name or control_id == "smb1_protocol":
        if status == "SAFE":
            return {
                "summary": "SMBv1 legacy protocol is disabled.",
                "what_checked": "Checked whether obsolete Server Message Block version 1 (SMBv1) protocol is enabled on this system.",
                "what_it_means": "Your machine will not accept incoming SMBv1 requests, neutralizing legacy file-sharing vulnerabilities.",
                "why_it_matters": "SMBv1 lacks modern cryptographic integrity and was the primary remote execution vector exploited by WannaCry and NotPetya (via MS17-010 / EternalBlue).",
                "reference": "MS17-010 | CVE-2017-0144 | CIS Microsoft Windows Benchmark Section 18.3.1",
                "diagnostic_command": "powershell \"(Get-SmbServerConfiguration).EnableSMB1Protocol\"",
                "remediation_command": "powershell \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
                "verification_command": "powershell \"(Get-SmbServerConfiguration).EnableSMB1Protocol\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Disables SMBv1 immediately. Note: Legacy Windows XP or archaic NAS drives that only speak SMBv1 will not be able to connect.",
                "cli_command": "powershell \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
                "next_steps": [
                    "No action required. SMBv1 is disabled.",
                    "Modern networks use SMBv2 and SMBv3 for authenticated, encrypted file sharing."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "SMBv1 legacy protocol is enabled on this machine.",
                "what_checked": "Checked SMBv1 server configuration.",
                "what_it_means": "The deprecated SMBv1 protocol is active and listening for local network connections.",
                "why_it_matters": "SMBv1 is an obsolete protocol with architectural flaws that allow unauthenticated remote code execution and lateral movement (exploited by WannaCry / MS17-010).",
                "reference": "MS17-010 | CVE-2017-0144 | CIS Microsoft Windows Benchmark Section 18.3.1",
                "diagnostic_command": "powershell \"(Get-SmbServerConfiguration).EnableSMB1Protocol\"",
                "remediation_command": "powershell \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
                "verification_command": "powershell \"(Get-SmbServerConfiguration).EnableSMB1Protocol\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Disables SMBv1 server protocol immediately without reboot. To fully remove OS feature drivers, use Windows Features GUI (optional reboot).",
                "cli_command": "powershell \"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\"",
                "next_steps": [
                    "Run in an Administrator PowerShell terminal: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                    "Or press Windows Key + R, type 'optionalfeatures.exe', uncheck 'SMB 1.0/CIFS File Sharing Support', and click 'OK'."
                ]
            }

    # 8. Remote Desktop (RDP) & Network Level Authentication (NLA)
    if "Remote Desktop" in name or "RDP" in name or control_id == "rdp_nla":
        if status == "SAFE":
            return {
                "summary": "Remote Desktop is either disabled or protected with Network Level Authentication (NLA).",
                "what_checked": "Checked whether RDP incoming connections are enabled (fDenyTSConnections) and if NLA pre-authentication is enforced.",
                "what_it_means": "Remote connections cannot access the Windows login screen without first validating valid domain or local user credentials.",
                "why_it_matters": "NLA prevents unauthenticated users from initiating full RDP sessions, mitigating brute-force attacks and pre-auth vulnerabilities (like BlueKeep / CVE-2019-0708).",
                "reference": "CVE-2019-0708 (BlueKeep) | CIS Microsoft Windows Benchmark Section 18.9.65 | MITRE ATT&CK T1021.001",
                "diagnostic_command": "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication",
                "remediation_command": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "RDP clients must support NLA (supported by all Windows 7+ and modern macOS/Linux RDP clients).",
                "cli_command": "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication",
                "next_steps": [
                    "No action required. RDP is disabled or strictly requires NLA.",
                    "If Remote Desktop is unneeded, keep it disabled in Windows Settings > System > Remote Desktop."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Remote Desktop is exposed without Network Level Authentication (NLA) enforcement.",
                "what_checked": "Checked Remote Desktop settings and NLA requirement.",
                "what_it_means": "RDP connections can reach the login interface without pre-authenticating at the network layer.",
                "why_it_matters": "Without NLA, exposed RDP ports are susceptible to credential brute-forcing, denial-of-service, and remote code execution vulnerabilities.",
                "reference": "CVE-2019-0708 (BlueKeep) | CIS Microsoft Windows Benchmark Section 18.9.65 | MITRE ATT&CK T1021.001",
                "diagnostic_command": "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication",
                "remediation_command": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Enforces NLA requirement immediately. Older, non-NLA RDP clients will be rejected.",
                "cli_command": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Start > Settings > System > Remote Desktop.",
                    "Ensure 'Require computers to use Network Level Authentication to connect' is checked.",
                    "Or run from an Administrator terminal: reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f"
                ]
            }

    # 9. Potentially Unwanted Application (PUA) Protection
    if "PUA" in name or "Potentially Unwanted Application" in name or control_id == "pua_protection":
        if status == "SAFE":
            return {
                "summary": "Microsoft Defender PUA blocking is active.",
                "what_checked": "Checked Defender's Potentially Unwanted Application (PUAProtection) configuration.",
                "what_it_means": "Defender automatically identifies and blocks intrusive adware, software bundlers, and stealth cryptocurrency miners.",
                "why_it_matters": "PUAs degrade computer performance, inject aggressive ads, and often serve as trojan horse downloaders.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.8 | MITRE ATT&CK T1496",
                "diagnostic_command": "powershell \"(Get-MpPreference).PUAProtection\"",
                "remediation_command": "powershell \"Set-MpPreference -PUAProtection Enabled\"",
                "verification_command": "powershell \"(Get-MpPreference).PUAProtection\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Blocks bundled adware during third-party software installation.",
                "cli_command": "powershell \"(Get-MpPreference).PUAProtection\"",
                "next_steps": [
                    "No action required. PUA protection is active.",
                    "Inspect Defender detection logs if an intentional tool is quarantined."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Microsoft Defender PUA blocking is turned off or disabled.",
                "what_checked": "Checked Defender's PUAProtection setting.",
                "what_it_means": "Defender allows bundled adware and low-reputation software installers to run unless they contain severe malware.",
                "why_it_matters": "Without PUA protection, toolbars, aggressive adware, and cryptominers can install alongside legitimate software.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.8 | MITRE ATT&CK T1496",
                "diagnostic_command": "powershell \"(Get-MpPreference).PUAProtection\"",
                "remediation_command": "powershell \"Set-MpPreference -PUAProtection Enabled\"",
                "verification_command": "powershell \"(Get-MpPreference).PUAProtection\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Enables PUA blocking. Does not interfere with authorized applications.",
                "cli_command": "powershell \"Set-MpPreference -PUAProtection Enabled\"",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security > App & browser control.",
                    "Click 'Reputation-based protection settings' and switch 'Potentially unwanted app blocking' to 'On'.",
                    "Or run from an Administrator PowerShell terminal: Set-MpPreference -PUAProtection Enabled"
                ]
            }

    # 10. Defender Controlled Folder Access / Ransomware Guard
    if "Controlled Folder Access" in name or "Ransomware" in name or control_id == "controlled_folder_access":
        if status == "SAFE":
            return {
                "summary": "Defender Controlled Folder Access (Ransomware Guard) is active.",
                "what_checked": "Checked whether Windows Defender Controlled Folder Access is protecting personal user directories.",
                "what_it_means": "Only recognized and trusted applications can modify files inside protected folders (Documents, Pictures, Desktop).",
                "why_it_matters": "Ransomware attempts to bulk-encrypt user files. Controlled Folder Access acts as a defensive vault, blocking untrusted processes from altering your data.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.15 | MITRE ATT&CK T1486",
                "diagnostic_command": "powershell \"(Get-MpPreference).EnableControlledFolderAccess\"",
                "remediation_command": "powershell \"Set-MpPreference -EnableControlledFolderAccess Enabled\"",
                "verification_command": "powershell \"(Get-MpPreference).EnableControlledFolderAccess\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Untrusted executables cannot write to protected user folders. Legitimate custom apps can be allowed via Windows Security.",
                "cli_command": "powershell \"(Get-MpPreference).EnableControlledFolderAccess\"",
                "next_steps": [
                    "No action required. Controlled Folder Access is shielding personal folders.",
                    "To allow a newly installed app: Start > Windows Security > Virus & threat protection > Ransomware protection > Allow an app through Controlled folder access."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Defender Controlled Folder Access (Ransomware Guard) is disabled.",
                "what_checked": "Checked Defender Controlled Folder Access configuration.",
                "what_it_means": "Any running executable has standard file write access to your Documents, Pictures, and Desktop directories.",
                "why_it_matters": "If ransomware infects the user session, it can immediately begin modifying and encrypting personal files without OS folder-locking intervention.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.15 | MITRE ATT&CK T1486",
                "diagnostic_command": "powershell \"(Get-MpPreference).EnableControlledFolderAccess\"",
                "remediation_command": "powershell \"Set-MpPreference -EnableControlledFolderAccess Enabled\"",
                "verification_command": "powershell \"(Get-MpPreference).EnableControlledFolderAccess\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Protects Documents, Pictures, and Desktop folders from unauthorized modifications.",
                "cli_command": "powershell \"Set-MpPreference -EnableControlledFolderAccess Enabled\"",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security > Virus & threat protection.",
                    "Scroll down to 'Ransomware protection' > 'Manage ransomware protection'.",
                    "Switch 'Controlled folder access' to 'On'.",
                    "Or run from an Administrator PowerShell terminal: Set-MpPreference -EnableControlledFolderAccess Enabled"
                ]
            }

    # 11. PowerShell Script Block Logging
    if "Script Block Logging" in name or control_id == "script_block_logging":
        if status == "SAFE":
            return {
                "summary": "PowerShell Script Block Logging is enabled for forensic auditing.",
                "what_checked": "Checked the system-wide PowerShell ScriptBlockLogging policy.",
                "what_it_means": "The full de-obfuscated content of executed PowerShell code blocks is recorded in Windows Event Viewer (Event ID 4104).",
                "why_it_matters": "Attackers frequently use obfuscated or fileless PowerShell scripts. Script block logging captures executed commands in memory, providing forensic visibility.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.84.1 | MITRE ATT&CK T1059.001",
                "diagnostic_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
                "remediation_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging).EnableScriptBlockLogging\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Increases PowerShell operational event log volume. Safe and non-disruptive.",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
                "next_steps": [
                    "No action required. Script block logging is active.",
                    "Events are logged to: Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational (Event ID 4104)."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "PowerShell Script Block Logging is disabled or not configured.",
                "what_checked": "Checked the system-wide PowerShell ScriptBlockLogging policy.",
                "what_it_means": "PowerShell command execution does not generate detailed forensic event logs for code blocks executed in memory.",
                "why_it_matters": "Fileless malware and living-off-the-land scripts can execute without leaving complete command trails in the Windows Event Log, hindering incident response.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.84.1 | MITRE ATT&CK T1059.001",
                "diagnostic_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
                "remediation_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging).EnableScriptBlockLogging\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Enables forensic auditing of PowerShell execution. Safe and recommended by CIS.",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Administrator terminal and run: reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                    "Or open gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > 'Turn on PowerShell Script Block Logging' > Enabled."
                ]
            }

    # 12. Anonymous SAM & Share Enumeration
    if "Anonymous" in name or "RestrictAnonymous" in name or control_id == "restrict_anonymous":
        if status == "SAFE":
            return {
                "summary": "Anonymous network enumeration of local accounts and shares is restricted.",
                "what_checked": "Checked LSA security policy (RestrictAnonymous).",
                "what_it_means": "Unauthenticated network clients cannot query local usernames, Security Identifiers (SIDs), or network share names without valid credentials.",
                "why_it_matters": "Restricting anonymous enumeration prevents reconnaissance tools from mapping user accounts and shares prior to launching targeted attacks.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.11.2 | MITRE ATT&CK T1087",
                "diagnostic_command": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous",
                "remediation_command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa).RestrictAnonymous\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Unauthenticated network discovery queries to the Local Security Authority are blocked. Standard authenticated network shares function normally.",
                "cli_command": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous",
                "next_steps": [
                    "No action required. Anonymous reconnaissance is restricted.",
                    "Ensure user accounts maintain strong, distinct passwords."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Anonymous SAM account and share enumeration is permitted.",
                "what_checked": "Checked LSA security policy (RestrictAnonymous).",
                "what_it_means": "Unauthenticated users or machines on the local network can query usernames and list shared folders without logging in.",
                "why_it_matters": "Reconnaissance is the initial phase of cyberattacks. Permitting anonymous queries gives attackers a full list of usernames to target with password-spraying attacks.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.11.2 | MITRE ATT&CK T1087",
                "diagnostic_command": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous",
                "remediation_command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                "verification_command": "powershell \"(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa).RestrictAnonymous\"",
                "requires_elevation": True,
                "requires_restart": False,
                "potential_impact": "Blocks anonymous SAM account lookups from unauthenticated network sessions.",
                "cli_command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Administrator terminal and run: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                    "Or open secpol.msc > Local Policies > Security Options > 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' > Enabled."
                ]
            }

    # Fallbacks for NOT_APPLICABLE, UNKNOWN, ERROR, TIMEOUT
    if status == "NOT_APPLICABLE":
        return {
            "summary": "This check is not applicable to the current operating environment.",
            "what_checked": f"Attempted to evaluate {name}.",
            "what_it_means": "The underlying management tool or Windows API is not applicable on this operating system edition or non-Windows host.",
            "why_it_matters": "Cyber Mistake Detector uses native Windows management cmdlets and registry keys.",
            "reference": "Environment Compatibility",
            "diagnostic_command": "ver",
            "remediation_command": "",
            "verification_command": "",
            "requires_elevation": False,
            "requires_restart": False,
            "potential_impact": "None.",
            "cli_command": "",
            "next_steps": [
                "Run Cyber Mistake Detector directly on a supported Windows 10 or Windows 11 machine to audit live controls."
            ]
        }

    if status in ("UNKNOWN", "TIMEOUT"):
        return {
            "summary": "The scanner could not conclusively verify this setting.",
            "what_checked": f"Attempted to check {name}.",
            "what_it_means": f"The query returned inconclusive data or timed out. Details: {details or 'Inconclusive query'}.",
            "why_it_matters": "An unknown result does not mean your PC is insecure; automated inspection could not confirm the state.",
            "reference": "Defensive Verification",
            "diagnostic_command": "",
            "remediation_command": "",
            "verification_command": "",
            "requires_elevation": False,
            "requires_restart": False,
            "potential_impact": "None.",
            "cli_command": "",
            "next_steps": [
                "Review this setting manually via Windows Settings or Windows Security.",
                "Ensure your user account has standard query access."
            ]
        }

    if status == "ERROR":
        return {
            "summary": "An execution error occurred while running this check.",
            "what_checked": f"Attempted to query {name}.",
            "what_it_means": f"The probe encountered an unexpected error. Details: {details or 'Execution error'}.",
            "why_it_matters": "A check error is not proof of a vulnerability. System errors can occur due to permission restrictions or missing cmdlets.",
            "reference": "Diagnostic Log",
            "diagnostic_command": "",
            "remediation_command": "",
            "verification_command": "",
            "requires_elevation": False,
            "requires_restart": False,
            "potential_impact": "None.",
            "cli_command": "",
            "next_steps": [
                "Try refreshing the scan.",
                "Review the setting manually via Windows Settings."
            ]
        }

    if status in ("NOT SUPPORTED", "NOT_SUPPORTED", "NOT_APPLICABLE"):
        return {
            "summary": "This check is not supported on the current operating environment.",
            "what_checked": f"Attempted to check {name}.",
            "what_it_means": f"This control requires Windows native APIs and is not supported in this environment. Details: {details}",
            "why_it_matters": "Operating system security checks require compatible platform APIs.",
            "reference": "Platform Compatibility",
            "diagnostic_command": "",
            "remediation_command": "",
            "verification_command": "",
            "requires_elevation": False,
            "requires_restart": False,
            "potential_impact": "None.",
            "cli_command": "",
            "next_steps": [
                "Run this scan directly on a native Windows workstation."
            ]
        }

    # General Fallback
    return {
        "summary": "Security finding recorded for review.",
        "what_checked": f"Evaluated setting: {name}.",
        "what_it_means": f"Status reported as {status}. Details: {details}",
        "why_it_matters": "Understanding each security setting helps you maintain good security hygiene.",
        "reference": "Security Baseline",
        "diagnostic_command": "",
        "remediation_command": "",
        "verification_command": "",
        "requires_elevation": False,
        "requires_restart": False,
        "potential_impact": "None.",
        "cli_command": "",
        "next_steps": [
            "Review this configuration in Windows Settings or Windows Security."
        ]
    }
