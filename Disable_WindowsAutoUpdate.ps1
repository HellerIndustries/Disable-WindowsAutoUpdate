# ============================================
# Disable Windows Update
# Run as Administrator
# ============================================

Write-Host "=== Aggressive Windows Update Disable ===" -ForegroundColor Cyan

# 1. Kill all update processes first
Write-Host "`nKilling update processes..." -ForegroundColor Yellow
$processesToKill = @('WaaSMedicAgent', 'UsoClient', 'WuaucltCore', 'sihclient', 'MoUsoCoreWorker')
foreach ($proc in $processesToKill) {
    Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
}

# 2. Disable ALL update-related services (expanded list)
$services = @(
    'wuauserv',      # Windows Update
    'UsoSvc',        # Update Orchestrator
    'BITS',          # Background Intelligent Transfer
    'WaaSMedicSvc',  # Windows Update Medic 
    'DoSvc',         # Delivery Optimization
    'sedsvc',        # Windows Remediation Service 
    'uhssvc',        # Microsoft Update Health Service
    'WUSM'           # Windows Update Service Manager (if exists)
)

foreach ($svc in $services) {
    Write-Host "Processing: $svc" -ForegroundColor Gray
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    
    # Force registry value
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -ErrorAction SilentlyContinue
        Write-Host "  Disabled via registry" -ForegroundColor Green
    }
}

# 3. CRITICAL: Lock down WaaSMedicSvc registry permissions
# This prevents Windows from re-enabling it
Write-Host "`nLocking WaaSMedicSvc registry permissions..." -ForegroundColor Yellow

$waasRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
try {
    # Get the registry key
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SYSTEM\CurrentControlSet\Services\WaaSMedicSvc",
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    
    if ($key) {
        $acl = $key.GetAccessControl()
        
        # Remove inherited permissions
        $acl.SetAccessRuleProtection($true, $false)
        
        # Add SYSTEM with read-only (can't modify Start value)
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $systemSid,
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($systemRule)
        
        # Add Administrators with full control (so you can undo this later)
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($adminRule)
        
        $key.SetAccessControl($acl)
        $key.Close()
        Write-Host "  WaaSMedicSvc registry locked!" -ForegroundColor Green
    }
}
catch {
    Write-Host "  Could not lock WaaSMedicSvc: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Trying alternate method..." -ForegroundColor Yellow
    
    # Alternate: Use SubInACL if available, or reg.exe
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f 2>&1 | Out-Null
}

# 4. Same for sedsvc (Remediation Service)
try {
    $sedsvcPath = "SYSTEM\CurrentControlSet\Services\sedsvc"
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $sedsvcPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )
    
    if ($key) {
        $acl = $key.GetAccessControl()
        $acl.SetAccessRuleProtection($true, $false)
        
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $systemSid,
            [System.Security.AccessControl.RegistryRights]::ReadKey,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($systemRule)
        
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($adminRule)
        
        $key.SetAccessControl($acl)
        $key.Close()
        Write-Host "  sedsvc registry locked!" -ForegroundColor Green
    }
}
catch {
    Write-Host "  sedsvc not present or couldn't lock" -ForegroundColor Gray
}

# 5. Policy registry keys
Write-Host "`nSetting policy registry keys..." -ForegroundColor Yellow

$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

if (-not (Test-Path $wuPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -Force | Out-Null
}
if (-not (Test-Path $auPath)) {
    New-Item -Path $wuPath -Name "AU" -Force | Out-Null
}

Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 1 -Type DWord
Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 1 -Type DWord
Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 1 -Type DWord

# Additional policy to disable Windows Update Medic Service
Set-ItemProperty -Path $wuPath -Name "DisableWUfBSafeguards" -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  Policy keys set" -ForegroundColor Green

# 6. Disable ALL update scheduled tasks (comprehensive list)
Write-Host "`nDisabling scheduled tasks..." -ForegroundColor Yellow

$tasks = @(
    '\Microsoft\Windows\WindowsUpdate\Scheduled Start'
    '\Microsoft\Windows\WindowsUpdate\sih'
    '\Microsoft\Windows\WindowsUpdate\sihboot'
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan'
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task'
    '\Microsoft\Windows\UpdateOrchestrator\Schedule Work'
    '\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker'
    '\Microsoft\Windows\UpdateOrchestrator\Reboot'
    '\Microsoft\Windows\UpdateOrchestrator\Reboot_AC'
    '\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery'
    '\Microsoft\Windows\UpdateOrchestrator\Refresh Settings'
    '\Microsoft\Windows\UpdateOrchestrator\Report policies'
    '\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask'
    '\Microsoft\Windows\UpdateOrchestrator\USO_Broker_Display'
    '\Microsoft\Windows\UpdateOrchestrator\PerformRemediation'
    '\Microsoft\Windows\WaaSMedic\PerformRemediation'
    '\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319'
    '\Microsoft\Windows\UNP\RunUpdateNotificationMgr'
    '\Microsoft\Windows\InstallService\ScanForUpdates'
    '\Microsoft\Windows\InstallService\ScanForUpdatesAsUser'
)

foreach ($task in $tasks) {
    $result = schtasks /Change /TN $task /Disable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Disabled: $task" -ForegroundColor Green
    }
}

# 7. Rename/disable key executables
Write-Host "`nDisabling update executables..." -ForegroundColor Yellow

$executables = @(
    "$env:SystemRoot\System32\UsoClient.exe"
    "$env:SystemRoot\System32\WaaSMedicAgent.exe"
    "$env:SystemRoot\System32\WaaSMedic.exe"
    "$env:SystemRoot\System32\MoUsoCoreWorker.exe"
)

foreach ($exe in $executables) {
    if (Test-Path $exe) {
        $bakPath = "$exe.disabled"
        if (-not (Test-Path $bakPath)) {
            try {
                takeown /f $exe 2>&1 | Out-Null
                icacls $exe /grant Administrators:F 2>&1 | Out-Null
                Rename-Item $exe $bakPath -Force -ErrorAction Stop
                Write-Host "  Renamed: $(Split-Path $exe -Leaf)" -ForegroundColor Green
            }
            catch {
                # If rename fails, try removing execute permission
                icacls $exe /deny "Everyone:(X)" 2>&1 | Out-Null
                Write-Host "  Blocked execution: $(Split-Path $exe -Leaf)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  Already disabled: $(Split-Path $exe -Leaf)" -ForegroundColor Gray
        }
    }
}

# 8. Block Windows Update servers via hosts file (extra layer for when online)
Write-Host "`nAdding hosts file blocks (optional layer)..." -ForegroundColor Yellow

$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$blockEntries = @(
    "0.0.0.0 update.microsoft.com"
    "0.0.0.0 windowsupdate.microsoft.com"
    "0.0.0.0 download.windowsupdate.com"
    "0.0.0.0 wustat.windows.com"
    "0.0.0.0 ntservicepack.microsoft.com"
)

$hostsContent = Get-Content $hostsFile -Raw -ErrorAction SilentlyContinue
$added = $false

foreach ($entry in $blockEntries) {
    if ($hostsContent -notlike "*$entry*") {
        Add-Content -Path $hostsFile -Value $entry -ErrorAction SilentlyContinue
        $added = $true
    }
}

if ($added) {
    Write-Host "  Hosts file updated" -ForegroundColor Green
}
else {
    Write-Host "  Hosts entries already present" -ForegroundColor Gray
}

# 9. Flush DNS cache
ipconfig /flushdns 2>&1 | Out-Null

Write-Host "`n=== COMPLETE ===" -ForegroundColor Cyan
Write-Host "Reboot required." -ForegroundColor Yellow
Write-Host "`nIf services re-enable again, the registry permission lock should prevent it." -ForegroundColor Gray
