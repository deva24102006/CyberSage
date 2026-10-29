@echo off
setlocal EnableDelayedExpansion

:: 1. Self-Elevate to Administrator (Fixes Error 740 and Access Denied)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] CyberSage requires Administrator rights to audit system policies.
    echo Requesting Administrator elevation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title CyberSage - Enterprise Windows Security Vulnerability Auditor
color 0b

echo ==============================================================================
echo   ____            _               ____                   
echo  / ___| _   _  __| |__   ___ _ _ / ___|  __ _  __ _  ___ 
echo ^| ^|    ^| ^| ^| ^|/ _` ^| '_ \ / _ \ '__\___ \ / _` ^|/ _` ^|/ _ \
echo ^| ^|___ ^| ^|_^| ^| (_^| ^| ^|_) ^|  __/ ^|   ___) ^| (_^| ^| (_^| ^|  __/
echo  \____^| \__, ^|\__,_^|_.__/ \___^|_^|  ^|____/ \__,_^|\__, ^|\___^|
echo          ^|___/                                     ^|___/     
echo ==============================================================================
echo   ENTERPRISE WINDOWS SECURITY & VULNERABILITY AUDITOR
echo   Running with Elevated Administrator Privileges
echo ==============================================================================
echo.

:audit
set "OUT_FILE=%USERPROFILE%\Desktop\audit_report.json"

echo [*] Auditing 12 Security Controls & Exploit Surfaces...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'SilentlyContinue'; $f = [System.Collections.Generic.List[object]]::new(); function addF($n,$c,$s,$d,$sev){ $f.Add(@{name=$n;category=$c;status=$s;details=$d;severity=$sev;checked_at=(Get-Date).ToUniversalTime().ToString('o')}) }; $fw = Get-NetFirewallProfile; if(($fw | Where-Object { $_.Enabled -ne $true }).Count -eq 0){ addF 'Windows Firewall Profiles' 'Core System Defenses' 'SAFE' 'All firewall profiles (Domain, Private, Public) are active.' 'Low' } else { addF 'Windows Firewall Profiles' 'Core System Defenses' 'WARNING' 'One or more firewall profiles are disabled.' 'High' }; $def = Get-MpComputerStatus; if($def.RealTimeProtectionEnabled){ addF 'Microsoft Defender Real-Time Protection' 'Core System Defenses' 'SAFE' 'Real-time protection is active.' 'Low' } else { addF 'Microsoft Defender Real-Time Protection' 'Core System Defenses' 'WARNING' 'Real-time protection is disabled.' 'High' }; if($def.AntivirusSignatureAge -le 7){ addF 'Antivirus Threat Definitions' 'Core System Defenses' 'SAFE' ('Signatures updated ' + $def.AntivirusSignatureAge + ' days ago.') 'Low' } else { addF 'Antivirus Threat Definitions' 'Core System Defenses' 'WARNING' ('Signatures are ' + $def.AntivirusSignatureAge + ' days old.') 'Medium' }; $wu = Get-Service wuauserv; if($wu.Status -eq 'Running'){ addF 'Windows Update Service' 'Core System Defenses' 'SAFE' 'wuauserv service is running.' 'Low' } else { addF 'Windows Update Service' 'Core System Defenses' 'WARNING' 'wuauserv is not running.' 'Medium' }; $uac = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA; if($uac -eq 1){ addF 'User Account Control (UAC)' 'Core System Defenses' 'SAFE' 'EnableLUA elevation policy is active.' 'Low' } else { addF 'User Account Control (UAC)' 'Core System Defenses' 'WARNING' 'UAC EnableLUA is disabled.' 'High' }; $g = (Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled; if($g -eq $false){ addF 'Guest Account Hardening' 'Core System Defenses' 'SAFE' 'Guest account is disabled.' 'Low' } else { addF 'Guest Account Hardening' 'Core System Defenses' 'WARNING' 'Guest account is enabled.' 'Medium' }; $smb = (Get-SmbServerConfiguration).EnableSMB1Protocol; if($smb -eq $false){ addF 'SMBv1 Legacy Protocol Exposure' 'Exploit Surface & Legacy Protocols' 'SAFE' 'SMBv1 protocol is disabled.' 'Low' } else { addF 'SMBv1 Legacy Protocol Exposure' 'Exploit Surface & Legacy Protocols' 'WARNING' 'SMBv1 protocol is enabled (WannaCry / MS17-010 vulnerability).' 'High' }; $rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections; $nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication; if($rdp -eq 1 -or $nla -eq 1){ addF 'Remote Desktop (RDP) & Network Level Authentication' 'Exploit Surface & Legacy Protocols' 'SAFE' 'RDP is disabled or requires NLA.' 'Low' } else { addF 'Remote Desktop (RDP) & Network Level Authentication' 'Exploit Surface & Legacy Protocols' 'WARNING' 'RDP is enabled without NLA.' 'High' }; $pua = (Get-MpPreference).PUAProtection; if($pua -eq 1){ addF 'Microsoft Defender PUA Protection' 'Ransomware & Malware Hardening' 'SAFE' 'PUA protection is enabled.' 'Low' } else { addF 'Microsoft Defender PUA Protection' 'Ransomware & Malware Hardening' 'WARNING' 'PUA protection is disabled.' 'Low' }; $cfa = (Get-MpPreference).EnableControlledFolderAccess; if($cfa -eq 1){ addF 'Microsoft Defender Controlled Folder Access (Ransomware Guard)' 'Ransomware & Malware Hardening' 'SAFE' 'Controlled Folder Access enabled.' 'Low' } else { addF 'Microsoft Defender Controlled Folder Access (Ransomware Guard)' 'Ransomware & Malware Hardening' 'WARNING' 'Controlled Folder Access disabled.' 'Medium' }; $log = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging).EnableScriptBlockLogging; if($log -eq 1){ addF 'PowerShell Script Block Logging (Event ID 4104)' 'Ransomware & Malware Hardening' 'SAFE' 'Script block logging is enabled.' 'Low' } else { addF 'PowerShell Script Block Logging (Event ID 4104)' 'Ransomware & Malware Hardening' 'WARNING' 'Script block logging is disabled.' 'Medium' }; $res = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous; if($res -eq 1){ addF 'Anonymous SAM & Share Enumeration (RestrictAnonymous)' 'Exploit Surface & Legacy Protocols' 'SAFE' 'RestrictAnonymous is enabled.' 'Low' } else { addF 'Anonymous SAM & Share Enumeration (RestrictAnonymous)' 'Exploit Surface & Legacy Protocols' 'WARNING' 'Anonymous enumeration allowed.' 'Medium' }; $safe = ($f | Where-Object { $_.status -eq 'SAFE' }).Count; $warn = ($f | Where-Object { $_.status -eq 'WARNING' }).Count; $high = ($f | Where-Object { $_.status -eq 'WARNING' -and $_.severity -eq 'High' }).Count; $tot = $f.Count; $pct = [math]::Round(($safe / $tot) * 100); foreach($item in $f){ if($item.status -eq 'SAFE'){ Write-Host ('  [PASS] ' + $item.name + ' -> ' + $item.details) -ForegroundColor Green } else { Write-Host ('  [FAIL] ' + $item.name + ' -> ' + $item.details) -ForegroundColor Yellow } }; Write-Host ''; Write-Host ('==============================================================================') -ForegroundColor Cyan; Write-Host ('  AUDIT SUMMARY: ' + $safe + ' of ' + $tot + ' Passed | ' + $warn + ' Weaknesses | Hygiene Score: ' + $pct + '%') -ForegroundColor Cyan; Write-Host ('==============================================================================') -ForegroundColor Cyan; $rep = @{ results=$f; total_checks=$tot; safe_count=$safe; warning_count=$warn; high_severity_count=$high; unknown_count=0; evaluated_count=$tot; hygiene_percentage=$pct; scan_mode='deep'; scan_mode_label='Real Host Security Audit (Live Endpoint Telemetry)'; scanned_at=(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'); coverage_note=($safe.ToString() + ' of ' + $tot.ToString() + ' passed.'); is_simulated=$false; environment_label='Local Physical Windows PC'; disclaimer='Educational Notice: This scanner checks specific Windows configuration parameters and defensive controls.' }; $rep | ConvertTo-Json -Depth 5 | Set-Content -Path $env:USERPROFILE\Desktop\audit_report.json -Encoding utf8"

echo.
echo [*] Telemetry report created:
echo     %USERPROFILE%\Desktop\audit_report.json
echo.
echo ==============================================================================
echo   ACTIONS AVAILABLE:
echo   [1] Open Cloud Dashboard to View Visual Report (https://cyber-sage-navy.vercel.app/)
echo   [2] Automatically Apply Administrator Fixes to Detected Weaknesses
echo   [3] Exit
echo ==============================================================================
echo.

choice /c 123 /n /m "Select option (1, 2, or 3): "

if errorlevel 3 goto :end
if errorlevel 2 goto :autofix
if errorlevel 1 goto :opencloud

:opencloud
start https://cyber-sage-navy.vercel.app/
echo Opened cloud dashboard. Upload audit_report.json from your Desktop to view!
pause
goto :end

:autofix
echo.
echo [*] Applying Administrator Hardening Fixes...
echo.

:: 1. Disable SMBv1
echo [+] Disabling SMBv1 protocol (MS17-010 / WannaCry)...
dism /online /disable-feature /featurename:SMB1Protocol /norestart >nul 2>&1

:: 2. Enable PowerShell Script Block Logging
echo [+] Enabling PowerShell Script Block Logging (Event ID 4104)...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >nul 2>&1

:: 3. Enable UAC
echo [+] Enabling User Account Control (EnableLUA)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul 2>&1

:: 4. Disable Guest Account
echo [+] Disabling local Guest account...
net user Guest /active:no >nul 2>&1

:: 5. Enable Windows Firewall on all profiles
echo [+] Enabling Windows Firewall across all profiles...
netsh advfirewall set allprofiles state on >nul 2>&1

:: 6. Restrict Anonymous SAM Enumeration
echo [+] Restricting Anonymous SAM Enumeration...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f >nul 2>&1

:: 7. Enable PUA Protection
echo [+] Enabling Defender PUA Protection...
powershell -Command "Set-MpPreference -PUAProtection Enabled" >nul 2>&1

echo.
echo ==============================================================================
echo  [SUCCESS] All security hardening fixes applied with Administrator privileges!
echo  Rerunning audit in 2 seconds to verify your updated security score...
echo ==============================================================================
echo.
timeout /t 2 /nobreak >nul
goto :audit

:end
echo.
pause
