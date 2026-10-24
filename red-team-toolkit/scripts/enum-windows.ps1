# enum-windows.ps1
# Full Windows enumeration for red teaming
# Run: powershell -ExecutionPolicy Bypass -File enum-windows.ps1

Write-Host "=== RED TEAM ENUMERATION ===" -ForegroundColor Cyan
Write-Host ""

# 1. System Info
Write-Host "--- SYSTEM INFO ---" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) (Build $($os.BuildNumber))"
Write-Host "Architecture: $($os.OSArchitecture)"
Write-Host "Computer Name: $env:COMPUTERNAME"
Write-Host "Domain/Workgroup: $(if ($env:USERDOMAIN) { $env:USERDOMAIN } else { 'N/A' })"
Write-Host "Logged in User: $env:USERNAME`@$env:USERDOMAIN"
Write-Host "UAC Status: $(if ([int](Get-CimInstance Win32_OperatingSystem).UIRequired).ToString() -eq 0) {'Enabled'} else {'Disabled'}"
Write-Host ""

# 2. Users & Groups
Write-Host "--- USERS ---" -ForegroundColor Yellow
Get-WmiObject Win32_UserAccount | Where-Object { $_.Disabled -eq $false } | ForEach-Object {
    Write-Host "  $($_.Name) ($($_.Domain)) - LocalGroup: $($_.LocalAccount)"
}
Write-Host ""

# 3. Privileges
Write-Host "--- CURRENT PRIVILEGES ---" -ForegroundColor Yellow
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
Write-Host "Is Admin: $($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-Host "Groups:"
$principal.Groups | ForEach-Object { Write-Host "  - $($_.Translate().ToString())" }
Write-Host ""

# 4. Services (non-Microsoft, started)
Write-Host "--- STARTED SERVICES ---" -ForegroundColor Yellow
Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -notlike '*\System32\svchost.exe*' } | ForEach-Object {
    Write-Host "  $($_.DisplayName) -> $($_.PathName)"
}
Write-Host ""

# 5. Network Connections
Write-Host "--- NETWORK CONNECTIONS ---" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess -First 20 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "  $($_.LocalAddress):$($_.LocalPort) -> $($proc.ProcessName)"
}
Write-Host ""

# 6. Shares
Write-Host "--- SHARES ---" -ForegroundColor Yellow
Get-SmbShare | ForEach-Object {
    Write-Host "  $($_.Name) - $($_.Description) (Path: $($_.Path))"
}
Write-Host ""

# 7. Scheduled Tasks
Write-Host "--- SCHEDULED TASKS (non-Microsoft) ---" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '*\Microsoft*' } | Select-Object TaskName, TaskPath, State -First 15 | ForEach-Object {
    Write-Host "  $($_.TaskPath)\$($_.TaskName) [$($_.State)]"
}
Write-Host ""

# 8. Installed Software (top-level)
Write-Host "--- INSTALLED SOFTWARE ---" -ForegroundColor Yellow
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, InstallDate -First 20 | ForEach-Object {
    Write-Host "  $($_.DisplayName) v$($_.DisplayVersion)"
}
Write-Host ""

# 9. Firewall Rules (custom)
Write-Host "--- FIREWALL RULES ---" -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Action, Direction -First 15 | ForEach-Object {
    Write-Host "  $($_.DisplayName) [$($_.Action)] ($($_.Direction))"
}
Write-Host ""

# 10. Environment & PATH
Write-Host "--- ENVIRONMENT ---" -ForegroundColor Yellow
Write-Host "PATH: $($env:PATH -replace ';', ' | ')"
Write-Host "TEMP: $env:TEMP"
Write-Host "USERPROFILE: $env:USERPROFILE"
Write-Host ""

# 11. PowerShell Configuration
Write-Host "--- POWERSHELL ---" -ForegroundColor Yellow
Write-Host "PSVersion: $($PSVersionTable.PSVersion)"
Write-Host "ExecutionPolicy: $(Get-ExecutionPolicy)"
Write-Host "PSProfile: $((Get-Item $PROFILE).FullName)"
Write-Host ""

# 12. Interesting Files (world-writable)
Write-Host "--- WORLD-WRITABLE PATHS ---" -ForegroundColor Yellow
$paths = @($env:SystemDrive, $env:TEMP, $env:USERPROFILE)
foreach ($p in $paths) {
    if (Test-Path $p) {
        Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } | Select-Object FullName, LastWriteTime, Length -First 10 | ForEach-Object {
            Write-Host "  $($_.FullName) ($([math]::Round($_.Length/1KB)) KB)"
        }
    }
}

Write-Host ""
Write-Host "=== ENUMERATION COMPLETE ===" -ForegroundColor Cyan
