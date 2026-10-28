"""
Recommendations engine for Cyber Mistake Detector.

Translates raw security check findings into structured, beginner-friendly
educational recommendations that explain:
1. What was checked
2. What the result means
3. Why the setting matters (Attack Surface / Exploit Vector)
4. What the user can safely do next (Step-by-step GUI instructions)
5. Terminal Command (Standard Windows Terminal / Command Prompt quick fix)
6. Reference (CIS Benchmark / MITRE ATT&CK / CVE)
"""

from typing import Any, Dict


def get_recommendation(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a security check result with structured educational guidance.

    Args:
        result: A dictionary containing at least 'name' and 'status'.

    Returns:
        The updated dictionary with a structured 'recommendation' dictionary.
    """
    name = result.get("name", "")
    status = result.get("status", "UNKNOWN").upper()
    details = result.get("details", "")

    recommendation = _build_recommendation(name, status, details)

    enriched = dict(result)
    enriched["recommendation"] = recommendation
    return enriched


def _build_recommendation(name: str, status: str, details: str) -> Dict[str, Any]:
    """Generates structured recommendation based on check name and status."""

    # 1. Windows Firewall
    if "Firewall" in name:
        if status == "SAFE":
            return {
                "summary": "Windows Firewall is active across Domain, Private, and Public network profiles.",
                "what_checked": "Checked whether Windows Defender Firewall is enabled for Domain, Private, and Public network connections.",
                "what_it_means": "Your computer actively inspects and filters inbound network traffic across all network types.",
                "why_it_matters": "Firewalls block unauthorized incoming connections, network scanners, and automated network worms from probing open ports on your device.",
                "reference": "CIS Microsoft Windows Benchmark Section 9.1-9.3 | MITRE ATT&CK T1562.004",
                "cli_command": "netsh advfirewall show allprofiles",
                "next_steps": [
                    "No action required.",
                    "Keep Windows Firewall enabled for all network profiles.",
                    "You can verify your settings anytime at: Start > Settings > Privacy & security > Windows Security > Firewall & network protection."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "One or more Windows Firewall profiles are turned off.",
                "what_checked": "Checked Windows Defender Firewall profiles (Domain, Private, and Public).",
                "what_it_means": "At least one network profile is unprotected, meaning inbound network traffic is not being filtered on that network.",
                "why_it_matters": "Disabling a firewall profile allows devices on the same local network or the internet to attempt connections to background services running on your machine.",
                "reference": "CIS Microsoft Windows Benchmark Section 9.1-9.3 | MITRE ATT&CK T1562.004",
                "cli_command": "netsh advfirewall set allprofiles state on",
                "next_steps": [
                    "Open the Start menu and select 'Settings' (or press Windows Key + I).",
                    "Click on 'Privacy & security', then select 'Windows Security'.",
                    "Click on 'Firewall & network protection'.",
                    "Click on each profile showing 'Firewall is off' and switch the toggle to 'On'."
                ]
            }

    # 2. Microsoft Defender Real-Time Protection
    if "Defender Real-Time" in name or "Defender Antivirus" in name:
        if status == "SAFE":
            return {
                "summary": "Microsoft Defender real-time protection is active.",
                "what_checked": "Checked whether the Microsoft Defender Antivirus service and real-time scanning are running.",
                "what_it_means": "Active processes, files being opened or downloaded, and system memory are continuously monitored for known threats.",
                "why_it_matters": "Real-time protection detects and halts malware, spyware, and ransomware before they can execute or encrypt personal documents.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9 | MITRE ATT&CK T1562.001",
                "cli_command": "sc query WinDefend",
                "next_steps": [
                    "No action required.",
                    "Keep real-time protection enabled.",
                    "Avoid disabling protection when prompted by untrusted downloads or installation guides."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Real-time antivirus protection is currently turned off or inactive.",
                "what_checked": "Checked Microsoft Defender real-time protection status.",
                "what_it_means": "The system is not actively scanning files or background programs as they are accessed or downloaded.",
                "why_it_matters": "Without real-time scanning, malicious files can enter and execute without immediate interception.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9 | MITRE ATT&CK T1562.001",
                "cli_command": "reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /f",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Virus & threat protection'.",
                    "Under 'Virus & threat protection settings', select 'Manage settings'.",
                    "Switch 'Real-time protection' to 'On'.",
                    "Note: If you intentionally use a third-party antivirus (such as Bitdefender, Malwarebytes, or Norton), check that its protection is active instead."
                ]
            }

    # 3. Defender Signature Freshness
    if "Signature" in name or "Definition" in name:
        if status == "SAFE":
            return {
                "summary": "Antivirus signatures are up to date (updated within the past 7 days).",
                "what_checked": "Checked the age of Microsoft Defender security intelligence definition files.",
                "what_it_means": "Your antivirus has recent intelligence on known malware families, trojans, and malicious payloads.",
                "why_it_matters": "Cybercriminals release new malware variants daily. Fresh signatures ensure your system recognizes the newest threats.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.23",
                "cli_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "next_steps": [
                    "No action required.",
                    "Windows Update will automatically download fresh definition packages periodically."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Antivirus threat definitions are outdated (older than 7 days).",
                "what_checked": "Checked the age of Microsoft Defender security intelligence definition files.",
                "what_it_means": "The definition database has not been refreshed recently, meaning recent threat variants may not be detected.",
                "why_it_matters": "Outdated signatures create an intelligence gap where newer threats can slip past traditional signature-based detection.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.23",
                "cli_command": "\"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Virus & threat protection'.",
                    "Under 'Virus & threat protection updates', click 'Check for updates'.",
                    "Allow Windows to download and install the latest definitions."
                ]
            }

    # 4. Windows Update
    if "Windows Update" in name:
        if status == "SAFE":
            return {
                "summary": "Windows Update service is operational and recent update activity was verified.",
                "what_checked": "Checked the Windows Update system service (wuauserv) and recently installed hotfixes.",
                "what_it_means": "The operating system is configured to receive maintenance patches and security updates from Microsoft.",
                "why_it_matters": "Regular updates patch newly discovered security vulnerabilities in Windows components, preventing remote exploit attempts.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.10 | MITRE ATT&CK T1190",
                "cli_command": "sc query wuauserv",
                "next_steps": [
                    "No immediate action required.",
                    "Regularly review Start > Settings > Windows Update to ensure your PC installs monthly quality updates."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Windows Update service is disabled or blocked from updating.",
                "what_checked": "Checked the Windows Update service configuration.",
                "what_it_means": "The service responsible for retrieving security bulletins and operating system updates is disabled or non-responsive.",
                "why_it_matters": "When updates are halted, known security flaws remain unpatched, exposing your computer to known exploits.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.10 | MITRE ATT&CK T1190",
                "cli_command": "sc config wuauserv start= demand & net start wuauserv",
                "next_steps": [
                    "Press Windows Key + R, type 'services.msc', and press Enter.",
                    "Scroll down and locate 'Windows Update'.",
                    "Double-click it, change 'Startup type' to 'Manual' or 'Automatic', and click 'Start'.",
                    "Open Start > Settings > Windows Update and click 'Check for updates'."
                ]
            }

    # 5. User Account Control (UAC)
    if "User Account Control" in name or "UAC" in name:
        if status == "SAFE":
            return {
                "summary": "User Account Control (UAC) is enabled.",
                "what_checked": "Checked the Windows elevation policy (EnableLUA).",
                "what_it_means": "Applications cannot silently obtain administrative privileges without prompting for confirmation.",
                "why_it_matters": "UAC prevents rogue scripts, malicious installers, or background software from making changes to core system files without your knowledge.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.17 | MITRE ATT&CK T1548.002",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA",
                "next_steps": [
                    "No action required.",
                    "Always read the prompt carefully before clicking 'Yes' when an application requests administrative rights."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "User Account Control (UAC) appears to be disabled.",
                "what_checked": "Checked the Windows elevation policy (EnableLUA).",
                "what_it_means": "Elevation prompts are turned off; programs can run with administrative privileges without asking for approval.",
                "why_it_matters": "Without UAC, any malware or trojan running on your user account can silently alter system settings, disable defenses, or install backdoors.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.17 | MITRE ATT&CK T1548.002",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open the Start menu and type 'Change User Account Control settings'.",
                    "Click to open the control panel dialog.",
                    "Drag the slider up to the recommended default level ('Notify me only when apps try to make changes').",
                    "Click 'OK' and restart your PC if prompted."
                ]
            }

    # 6. Built-in Guest Account
    if "Guest Account" in name:
        if status == "SAFE":
            return {
                "summary": "The built-in Guest account is disabled.",
                "what_checked": "Checked whether the local Windows 'Guest' user account is active.",
                "what_it_means": "Unauthenticated or casual users cannot log in to your machine without valid, assigned account credentials.",
                "why_it_matters": "Disabling unnecessary and default accounts adheres to the principle of least privilege and reduces local attack surfaces.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.1.1 | MITRE ATT&CK T1078",
                "cli_command": "net user Guest",
                "next_steps": [
                    "No action required.",
                    "Keep unused and built-in guest accounts disabled."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "The built-in Guest account is currently active.",
                "what_checked": "Checked whether the local Windows 'Guest' user account is active.",
                "what_it_means": "The computer permits local sign-in using the built-in guest identity.",
                "why_it_matters": "Active guest accounts can be leveraged by unauthorized individuals with physical access or local network access to explore your files.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.1.1 | MITRE ATT&CK T1078",
                "cli_command": "net user Guest /active:no",
                "next_steps": [
                    "Press Windows Key + R, type 'lusrmgr.msc' (or open Computer Management > Local Users and Groups).",
                    "Click 'Users', then double-click the 'Guest' account.",
                    "Check the box 'Account is disabled', then click 'OK'.",
                    "Or open Command Prompt / Terminal as Administrator and run: net user Guest /active:no"
                ]
            }

    # 7. SMBv1 Legacy Protocol Exposure (Deep Scan)
    if "SMBv1" in name:
        if status == "SAFE":
            return {
                "summary": "SMBv1 legacy protocol is disabled.",
                "what_checked": "Checked whether the obsolete Server Message Block version 1 (SMBv1) protocol is enabled on this system.",
                "what_it_means": "Your machine will not accept incoming SMBv1 requests, neutralizing legacy file-sharing vulnerabilities.",
                "why_it_matters": "SMBv1 lacks modern cryptographic integrity and was the primary remote execution vulnerability exploited by destructive worms like WannaCry and NotPetya (via EternalBlue / MS17-010).",
                "reference": "MS17-010 | CVE-2017-0144 | CIS Microsoft Windows Benchmark Section 18.3.1",
                "cli_command": "dism /online /get-featureinfo /featurename:SMB1Protocol",
                "next_steps": [
                    "No action required.",
                    "Keep SMBv1 disabled on all systems. Modern networks use SMBv2 and SMBv3 for safe file sharing."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "SMBv1 legacy protocol is enabled on this machine.",
                "what_checked": "Checked SMBv1 server configuration.",
                "what_it_means": "The deprecated SMBv1 protocol is active and listening for local network connections.",
                "why_it_matters": "SMBv1 is an obsolete 30-year-old protocol with notorious architectural flaws that allow unauthenticated remote code execution and lateral movement (exploited by WannaCry and NotPetya via EternalBlue).",
                "reference": "MS17-010 | CVE-2017-0144 | CIS Microsoft Windows Benchmark Section 18.3.1",
                "cli_command": "dism /online /disable-feature /featurename:SMB1Protocol /norestart",
                "next_steps": [
                    "Press Windows Key + R, type 'optionalfeatures.exe', and press Enter.",
                    "Scroll down to 'SMB 1.0/CIFS File Sharing Support'.",
                    "Uncheck 'SMB 1.0/CIFS File Sharing Support' and click 'OK'.",
                    "Or open Terminal as Administrator and run: dism /online /disable-feature /featurename:SMB1Protocol /norestart",
                    "Restart your computer when prompted."
                ]
            }

    # 8. Remote Desktop (RDP) & Network Level Authentication (NLA) (Deep Scan)
    if "Remote Desktop" in name or "RDP" in name:
        if status == "SAFE":
            return {
                "summary": "Remote Desktop is either disabled or protected with Network Level Authentication (NLA).",
                "what_checked": "Checked whether RDP incoming connections are enabled (fDenyTSConnections) and if NLA pre-authentication is enforced.",
                "what_it_means": "Remote connections cannot access the Windows login screen without first validating valid domain or local user credentials.",
                "why_it_matters": "Network Level Authentication prevents unauthenticated users from initiating full RDP sessions, mitigating brute-force attacks and pre-auth vulnerabilities (like BlueKeep / CVE-2019-0708).",
                "reference": "CVE-2019-0708 (BlueKeep) | CIS Microsoft Windows Benchmark Section 18.9.65 | MITRE ATT&CK T1021.001",
                "cli_command": "reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections",
                "next_steps": [
                    "No action required.",
                    "If you do not need Remote Desktop, keep it turned off in Windows Settings > System > Remote Desktop."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Remote Desktop is exposed without Network Level Authentication (NLA) enforcement.",
                "what_checked": "Checked Remote Desktop settings and NLA requirement.",
                "what_it_means": "RDP connections can reach the login interface without pre-authenticating at the network layer.",
                "why_it_matters": "Without NLA, exposed RDP ports are susceptible to credential brute-forcing, denial-of-service, and remote code execution vulnerabilities.",
                "reference": "CVE-2019-0708 (BlueKeep) | CIS Microsoft Windows Benchmark Section 18.9.65 | MITRE ATT&CK T1021.001",
                "cli_command": "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Start > Settings > System > Remote Desktop.",
                    "Under Remote Desktop settings, ensure 'Require computers to use Network Level Authentication to connect' is checked.",
                    "If Remote Desktop is not actively needed, switch 'Remote Desktop' to 'Off'."
                ]
            }

    # 9. Potentially Unwanted Application (PUA) Protection (Deep Scan)
    if "PUA" in name or "Potentially Unwanted Application" in name:
        if status == "SAFE":
            return {
                "summary": "Microsoft Defender PUA blocking is active.",
                "what_checked": "Checked Defender's Potentially Unwanted Application (PUAProtection) configuration.",
                "what_it_means": "Defender automatically identifies and blocks intrusive adware, software bundlers, and stealth cryptocurrency miners.",
                "why_it_matters": "PUAs degrade computer performance, inject aggressive ads, and often serve as trojan horse downloaders for severe malware.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.8 | MITRE ATT&CK T1496",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v MpEnablePus",
                "next_steps": [
                    "No action required.",
                    "PUA protection will actively inspect downloaded installers and executables."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Microsoft Defender Potentially Unwanted Application (PUA) blocking is turned off.",
                "what_checked": "Checked Defender's PUAProtection setting.",
                "what_it_means": "Defender allows bundled adware and low-reputation software installers to run unless they contain known severe malware.",
                "why_it_matters": "Without PUA protection, software bundling toolbars, intrusive adware, and cryptominers can install alongside legitimate software.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.8 | MITRE ATT&CK T1496",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v MpEnablePus /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'App & browser control', then select 'Reputation-based protection settings'.",
                    "Under 'Potentially unwanted app blocking', switch the toggle to 'On'.",
                    "Ensure both 'Block apps' and 'Block downloads' checkboxes are enabled."
                ]
            }

    # 10. Defender Controlled Folder Access / Ransomware Guard (Deep Scan)
    if "Controlled Folder Access" in name or "Ransomware" in name:
        if status == "SAFE":
            return {
                "summary": "Defender Controlled Folder Access (Ransomware Guard) is active.",
                "what_checked": "Checked whether Windows Defender Controlled Folder Access is protecting personal user directories.",
                "what_it_means": "Only recognized and trusted applications can modify or write files inside protected folders (Documents, Pictures, Desktop, etc.).",
                "why_it_matters": "Ransomware attempts to bulk-encrypt user files. Controlled Folder Access acts as a defensive vault, blocking untrusted processes from altering your data.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.15 | MITRE ATT&CK T1486 (Data Encrypted for Impact)",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\" /v EnableControlledFolderAccess",
                "next_steps": [
                    "No action required.",
                    "If a legitimate application is ever blocked, you can allow it under Windows Security > Virus & threat protection > Ransomware protection > Allow an app through Controlled folder access."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Defender Controlled Folder Access (Ransomware Guard) is disabled.",
                "what_checked": "Checked Defender Controlled Folder Access configuration.",
                "what_it_means": "Any running executable has standard file write access to your Documents, Pictures, and Desktop directories.",
                "why_it_matters": "If ransomware infects the user session, it can immediately begin modifying and encrypting personal files without OS-level folder intervention.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.15 | MITRE ATT&CK T1486 (Data Encrypted for Impact)",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\" /v EnableControlledFolderAccess /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Open Start > Settings > Privacy & security > Windows Security.",
                    "Click 'Virus & threat protection', then scroll down to 'Ransomware protection'.",
                    "Click 'Manage ransomware protection'.",
                    "Switch 'Controlled folder access' to 'On'."
                ]
            }

    # 11. PowerShell Script Block Logging (Deep Scan)
    if "Script Block Logging" in name:
        if status == "SAFE":
            return {
                "summary": "PowerShell Script Block Logging is enabled for forensic auditing.",
                "what_checked": "Checked the system-wide PowerShell ScriptBlockLogging policy.",
                "what_it_means": "The full de-obfuscated content of executed PowerShell code blocks is recorded in Windows Event Viewer (Event ID 4104).",
                "why_it_matters": "Attackers frequently use obfuscated or fileless PowerShell scripts. Script block logging captures the actual executed commands in memory, providing forensic visibility.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.84.1 | MITRE ATT&CK T1059.001",
                "cli_command": "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
                "next_steps": [
                    "No action required.",
                    "Security event log auditing will record script executions for investigation."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "PowerShell Script Block Logging is disabled or not configured.",
                "what_checked": "Checked the system-wide PowerShell ScriptBlockLogging policy.",
                "what_it_means": "PowerShell command execution does not generate detailed forensic event logs for code blocks executed in memory.",
                "why_it_matters": "Fileless malware and living-off-the-land scripts can execute without leaving complete command trails in the Windows Event Log, hindering incident response.",
                "reference": "CIS Microsoft Windows Benchmark Section 18.9.84.1 | MITRE ATT&CK T1059.001",
                "cli_command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Press Windows Key + R, type 'gpedit.msc', and press Enter (Local Group Policy Editor).",
                    "Navigate to: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell.",
                    "Double-click 'Turn on PowerShell Script Block Logging'.",
                    "Select 'Enabled' and click 'OK'."
                ]
            }

    # 12. Anonymous SAM & Share Enumeration (Deep Scan)
    if "Anonymous" in name or "RestrictAnonymous" in name:
        if status == "SAFE":
            return {
                "summary": "Anonymous network enumeration of local accounts and shares is restricted.",
                "what_checked": "Checked LSA security policy (RestrictAnonymous).",
                "what_it_means": "Unauthenticated network clients cannot query local usernames, Security Identifiers (SIDs), or network share names without valid credentials.",
                "why_it_matters": "Restricting anonymous enumeration prevents reconnaissance tools from mapping user accounts and shares prior to launching targeted attacks.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.11.2 | MITRE ATT&CK T1087 (Account Discovery)",
                "cli_command": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous",
                "next_steps": [
                    "No action required.",
                    "Keep anonymous reconnaissance restricted."
                ]
            }
        elif status == "WARNING":
            return {
                "summary": "Anonymous SAM account and share enumeration is permitted.",
                "what_checked": "Checked LSA security policy (RestrictAnonymous).",
                "what_it_means": "Unauthenticated users or machines on the local network can query usernames and list shared folders without logging in.",
                "why_it_matters": "Reconnaissance is the initial phase of cyberattacks. Permitting anonymous queries gives attackers a full list of usernames to target with password-spraying or brute-force attacks.",
                "reference": "CIS Microsoft Windows Benchmark Section 2.3.11.2 | MITRE ATT&CK T1087 (Account Discovery)",
                "cli_command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                "next_steps": [
                    "Press Windows Key + R, type 'secpol.msc' (Local Security Policy).",
                    "Navigate to: Local Policies > Security Options.",
                    "Find 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'.",
                    "Double-click it, set to 'Enabled', and click 'OK'."
                ]
            }

    # Fallbacks for UNKNOWN, NOT SUPPORTED, ERROR
    if status == "NOT SUPPORTED":
        return {
            "summary": "This check is not supported on the current operating environment.",
            "what_checked": f"Attempted to evaluate {name}.",
            "what_it_means": "The underlying management tool is unavailable or running on a non-Windows OS.",
            "why_it_matters": "Cyber Mistake Detector uses Windows management cmdlets. Non-Windows systems or certain restricted editions cannot execute them.",
            "reference": "Environment Compatibility",
            "cli_command": "ver",
            "next_steps": [
                "Run Cyber Mistake Detector on a supported Windows 10 or Windows 11 machine.",
                "You can inspect system security settings manually using your operating system's security control panel."
            ]
        }

    if status == "UNKNOWN":
        return {
            "summary": "The scanner could not conclusively verify this setting.",
            "what_checked": f"Attempted to check {name}.",
            "what_it_means": "The command executed but returned inconclusive data, or access was restricted.",
            "why_it_matters": "An unknown result does not mean your PC is insecure; it simply means automated inspection could not confirm the state.",
            "reference": "Defensive Verification",
            "cli_command": "",
            "next_steps": [
                "Open Windows Security (Start > Settings > Privacy & security > Windows Security) to verify this setting manually.",
                "Ensure your user account has standard query permissions."
            ]
        }

    if status == "ERROR":
        return {
            "summary": "An execution error occurred while running this check.",
            "what_checked": f"Attempted to query {name}.",
            "what_it_means": f"The query failed during execution. Details: {details or 'Command execution error'}.",
            "why_it_matters": "A check error is not proof of a security vulnerability. System errors can occur due to command timeouts or permission restrictions.",
            "reference": "Diagnostic Log",
            "cli_command": "",
            "next_steps": [
                "Try running the scan again.",
                "If the problem persists, review the setting manually via Windows Settings."
            ]
        }

    # General Fallback
    return {
        "summary": "Security finding recorded for review.",
        "what_checked": f"Evaluated setting: {name}.",
        "what_it_means": f"Status reported as {status}. Details: {details}",
        "why_it_matters": "Understanding each security setting helps you maintain good security hygiene.",
        "reference": "Security Baseline",
        "cli_command": "",
        "next_steps": [
            "Review this configuration in Windows Settings or Windows Security.",
            "Consult Microsoft documentation if unsure."
        ]
    }
