# Cyber Mistake Detector

> **An enterprise-grade educational cybersecurity web application for auditing Windows security configurations, uncovering deep system vulnerabilities, and providing instant terminal remediation commands.**

---

## 1. Project Overview

**Cyber Mistake Detector** is a local defensive security auditing web application built with Python and Flask. It performs safe, read-only inspections of Windows operating systems to uncover critical configuration weaknesses, legacy protocol exposures, and missing ransomware defenses.

### Core Highlights
* **Safe & Read-Only:** All scans execute locally in read-only mode without modifying system files, disabling protections, or communicating externally.
* **Dual Scan Modes:** Choose between a fast **Quick Baseline Audit (6 controls)** and an extensive **Hard System Vulnerability Audit (12 controls)**.
* **Standard Terminal Remediation Commands:** In addition to step-by-step Windows Settings GUI guidance, every finding provides a universal Windows Terminal command (`netsh`, `dism`, `reg add`, `net user`, `sc`, `MpCmdRun.exe`) with a 1-click **Copy Command** button.
* **Compliance Alignment:** Findings map directly to authoritative standards including **CIS Microsoft Windows Benchmarks**, **MITRE ATT&CK Framework**, and **CVE bulletins** (such as MS17-010 EternalBlue and CVE-2019-0708 BlueKeep).

---

## 2. Hard Scan vs. Quick Scan Scope

### A. Exploit Surface & Legacy Protocols (Hard Scan)
| Check | Audit Method | Terminal Quick-Fix Command | Attack Vector / Risk |
| :--- | :--- | :--- | :--- |
| **SMBv1 Legacy Protocol** | `Get-SmbServerConfiguration` | `dism /online /disable-feature /featurename:SMB1Protocol /norestart` | **WannaCry / MS17-010:** Obsolete protocol susceptible to wormable remote code execution. |
| **Remote Desktop & NLA** | `fDenyTSConnections` & `UserAuthentication` | `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f` | **BlueKeep & Brute Force:** Exposing RDP without NLA allows unauthenticated pre-auth probing. |
| **Anonymous SAM & Shares** | `LSA RestrictAnonymous` | `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f` | **Network Reconnaissance:** Unauthenticated users can harvest local user accounts and shares. |

### B. Ransomware Defense & System Hardening (Hard Scan)
| Check | Audit Method | Terminal Quick-Fix Command | Attack Vector / Risk |
| :--- | :--- | :--- | :--- |
| **Controlled Folder Access** | `Get-MpPreference` | `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v EnableControlledFolderAccess /t REG_DWORD /d 1 /f` | **Ransomware Encryption:** Protects Documents, Pictures, and Desktop from unauthorized process encryption. |
| **Defender PUA Shield** | `Get-MpPreference` | `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpEnablePus /t REG_DWORD /d 1 /f` | **Adware & Coin-Miners:** Blocks bundled toolbars, aggressive adware, and stealth miners. |
| **PowerShell Script Logging** | `ScriptBlockLogging` | `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f` | **Fileless Malware:** Ensures memory-resident living-off-the-land scripts leave Event ID 4104 logs. |

### C. Core Defensive Baselines (Quick & Hard Scan)
| Check | Audit Method | Terminal Quick-Fix Command | Attack Vector / Risk |
| :--- | :--- | :--- | :--- |
| **Windows Firewall** | `Get-NetFirewallProfile` | `netsh advfirewall set allprofiles state on` | **Network Probing:** Filters unauthorized inbound network traffic across all interfaces. |
| **Defender Real-Time** | `Get-MpComputerStatus` | `sc query WinDefend` | **Malware Execution:** Continuous real-time process and memory scanning. |
| **Threat Signature Age** | `AntivirusSignatureAge` | `"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate` | **Zero-Day Exposure:** Updates threat definition intelligence within the 7-day threshold. |
| **Windows Update** | `Get-Service wuauserv` | `sc config wuauserv start= demand & net start wuauserv` | **Unpatched Vulnerabilities:** Retrieves monthly operating system quality and security patches. |
| **UAC Elevation Policy** | `EnableLUA` registry | `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f` | **Privilege Escalation:** Prevents background malware from silently seizing administrative rights. |
| **Guest Account** | `Get-LocalUser Guest` | `net user Guest /active:no` | **Least Privilege:** Deactivates unused default local accounts to minimize attack surfaces. |

---

## 3. How to Launch and Deploy

### Option A: Local Multi-Threaded Production Deployment (Windows / LAN)
Run with the high-performance, multi-threaded production WSGI server (**Waitress**):
* **1-Click Launch:** Double-click `run_production.bat`
* **Or via Terminal:**
  ```powershell
  python wsgi.py
  ```
The server binds to `0.0.0.0:5000` with 4 concurrent worker threads, ready to serve both the local machine and other machines across the local area network.

### Option B: 1-Click Free Cloud Deployment (Render Blueprint)
1. Fork or push this repository to your GitHub account (`https://github.com/deva24102006/CyberSage`).
2. Log into [Render.com](https://render.com) and click **New +** > **Blueprint**.
3. Select your repository. Render automatically reads `render.yaml` and deploys the app with `gunicorn wsgi:app` on the free tier.
4. Your application will be live at `https://your-app-name.onrender.com`.

### Option C: Universal Container Deployment (Docker)
Build and run anywhere (AWS ECS, Google Cloud Run, Azure App Service, or self-hosted Docker):
```bash
docker build -t cyber-mistake-detector .
docker run -d -p 5000:5000 cyber-mistake-detector
```

### Option D: Local Development Launch
```powershell
python app.py
```
Open your browser to: **[http://127.0.0.1:5000/](http://127.0.0.1:5000/)**

---

## 4. Auditing Remote Windows Endpoints via Cloud Deployment

When Cyber Mistake Detector is deployed in the cloud (Linux host):
1. Navigate to the cloud URL and click **Download Collector (.bat)** (`CyberSage_Scanner.bat`).
2. Run `CyberSage_Scanner.bat` on any physical Windows target PC with standard user privileges.
3. The collector executes safe, read-only PowerShell probes and exports `audit_report.json`.
4. Upload `audit_report.json` on the cloud web dashboard under **Endpoint Telemetry**.
5. The cloud engine automatically parses findings, computes the authoritative hygiene score, and runs the ML breach prediction model.

---

## 5. Automated Tests

Run the deterministic test suite:
```powershell
python -m unittest discover -s tests -v
```

**Status:** `62 passed, 0 failures, 0 errors` (in under 1 second).
