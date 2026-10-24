# attack-paths.ps1
# Identify and test common Windows privilege escalation paths
# Run: powershell -ExecutionPolicy Bypass -File attack-paths.ps1

Write-Host "=== PRIVILEGE ESCALATION PATHS ===" -ForegroundColor Cyan
Write-Host ""

$findings = @()

# 1. Unquoted Service Paths (classic)
Write-Host "--- UNQUOTED SERVICE PATHS ---" -ForegroundColor Yellow
$services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -notlike '*"*' -and $_.State -eq 'Running' }
foreach ($svc in $services) {
    if ($svc.PathName -match '\s[^ ]') {
        Write-Host "  [!] Unquoted: $($svc.Name) -> $($svc.PathName)"
        $findings += "Unquoted service path: $($svc.Name)"
    }
}
Write-Host ""

# 2. Weak Folder Permissions
Write-Host "--- WEAK FOLDER PERMISSIONS ---" -ForegroundColor Yellow
$weakFolders = @("C:\Program Files", "C:\Program Files (x86)", "C:\Windows")
foreach ($folder in $weakFolders) {
    if (Test-Path $folder) {
        $acl = Get-Acl $folder
        $rules = $acl.Access | Where-Object { $_.IdentityReference -notlike '*BUILTIN\Administrators*' -and $_.IdentityReference -notlike 'NT AUTHORITY\SYSTEM' }
        foreach ($rule in $rules) {
            if (($rule.FileSystemRights -match 'Write|Modify|Full') -and $rule.IdentityReference.ToString() -notlike '*Everyone*') {
                Write-Host "  [!] $($folder)\ -> $($rule.IdentityReference) has $($rule.FileSystemRights)"
                $findings += "Weak folder perm: $folder to $($rule.IdentityReference)"
            }
        }
    }
}
Write-Host ""

# 3. Registry Run Keys (persistence + escalation)
Write-Host "--- REGISTRY RUN KEYS ---" -ForegroundColor Yellow
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Get-ItemProperty $key | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Value } | ForEach-Object {
                Write-Host "  [$($key -replace 'HKLM:\\', '').Replace('HKCU:\', '')] $($_.Name) = $($_.Value)"
            }
        }
    }
}
Write-Host ""

# 4. DLL Search Order Hijacking
Write-Host "--- DLL SEARCH ORDER RISK ---" -ForegroundColor Yellow
$paths = ($env:PATH -split ';') + @("C:\Windows\System32", "C:\Windows")
foreach ($p in $paths) {
    if (Test-Path $p) {
        $acl = Get-Acl $p
        $everyoneWrite = $acl.Access | Where-Object { 
            $_.IdentityReference.ToString() -match 'Everyone|BUILTIN\Users' -and 
            ($_.FileSystemRights -match 'Write|Modify|Full') 
        }
        if ($everyoneWrite) {
            Write-Host "  [!] $p is writable by non-admins"
            $findings += "DLL hijack risk: $p"
        }
    }
}
Write-Host ""

# 5. AlwaysInstallElevated
Write-Host "--- MSI INSTALLATION ---" -ForegroundColor Yellow
$alwaysInstall = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$currentInstall = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
if ($alwaysInstall.AlwaysInstallElevated -eq 1) { Write-Host "  [!] HKLM AlwaysInstallElevated = 1" }
if ($currentInstall.AlwaysInstallElevated -eq 1) { Write-Host "  [!] HKCU AlwaysInstallElevated = 1" }
if (($alwaysInstall.AlwaysInstallElevated -eq 1) -and ($currentInstall.AlwaysInstallElevated -eq 1)) {
    Write-Host "  [!!] Both set — any user can install elevated MSI!"
    $findings += "AlwaysInstallElevated (both HKLM+HKCU)"
}
Write-Host ""

# 6. Credential Storage
Write-Host "--- CREDENTIALS ---" -ForegroundColor Yellow
Write-Host "  DPAPI encrypted, but check for:"
$credPath = "$env:APPDATA\Microsoft\Credentials"
if (Test-Path $credPath) {
    Write-Host "  [!] Credentials folder exists: $credPath"
}
# Check for stored passwords in common locations
Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Roaming\" -Recurse -Include "*.xml","*.json","*.ini","*.conf" -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 10KB } | Select-Object FullName, Length -First 5 | ForEach-Object {
    Write-Host "  [?] Config file: $($_.FullName)"
}
Write-Host ""

# 7. Token Privileges
Write-Host "--- TOKEN PRIVILEGES ---" -ForegroundColor Yellow
$privs = Get-CimInstance Win32_TokenPrivilege | Where-Object { $_.Enabled }
$interestingPrivs = @("SeDebugPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", 
                       "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnership")
foreach ($ip in $interestingPrivs) {
    $found = $privs | Where-Object { $_.Name -eq $ip }
    if ($found) { Write-Host "  [+] $ip" }
}
Write-Host ""

# 8. AutoLogon Credentials
Write-Host "--- AUTologon ---" -ForegroundColor Yellow
$autologon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($autologon.DefaultUserName) {
    Write-Host "  AutoLogon: $($autologon.DefaultUserName)"
    if ($autologon.DefaultPassword) {
        Write-Host "  [!] Password visible in registry!"
        $findings += "AutoLogon password exposed"
    }
}
Write-Host ""

# Summary
if ($findings.Count -gt 0) {
    Write-Host "=== FINDINGS SUMMARY ===" -ForegroundColor Yellow
    for ($i = 1; $i -le $findings.Count; $i++) {
        Write-Host "  $i. $($findings[$i-1])"
    }
} else {
    Write-Host "No significant findings." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== ATTACK PATH ANALYSIS COMPLETE ===" -ForegroundColor Cyan
