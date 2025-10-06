# Requires administrative privileges
# Ensure script is run as administrator
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrative privileges. Please run as Administrator."
    Exit
}

# Disable Windows Update via registry
$WUSettingsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
$WUSettings = @{
    "NoAutoUpdate" = 1  # Disable automatic updates
}

# Create or update registry path for Windows Update settings
If (-not (Test-Path $WUSettingsPath)) {
    New-Item -Path $WUSettingsPath -Force | Out-Null
}

# Apply settings to registry
foreach ($key in $WUSettings.Keys) {
    Set-ItemProperty -Path $WUSettingsPath -Name $key -Value $WUSettings[$key] -Force
}

# Set Group Policy equivalent to disable updates
$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
If (-not (Test-Path $PolicyPath)) {
    New-Item -Path $PolicyPath -Force | Out-Null
}

Set-ItemProperty -Path $PolicyPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Force
New-Item -Path "$PolicyPath\AU" -Force | Out-Null
Set-ItemProperty -Path "$PolicyPath\AU" -Name "NoAutoUpdate" -Value 1 -Force

# Stop and disable Windows Update-related services
$Services = @("wuauserv", "UsoSvc", "WaaSMedicSvc")  # Windows Update, Update Orchestrator, Windows Update Medic
foreach ($Service in $Services) {
    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
}

# Block Windows Update servers (optional, adds extra layer)
$HostsFile = "$env:windir\System32\drivers\etc\hosts"
$WUHosts = @(
    "0.0.0.0 windowsupdate.microsoft.com",
    "0.0.0.0 download.windowsupdate.com",
    "0.0.0.0 update.microsoft.com"
)

foreach ($Entry in $WUHosts) {
    If (-not (Select-String -Path $HostsFile -Pattern $Entry -Quiet)) {
        Add-Content -Path $HostsFile -Value $Entry
    }
}

Write-Host "Windows Update has been fully disabled."
Write-Host "Services stopped and disabled: wuauserv, UsoSvc, WaaSMedicSvc."
Write-Host "Windows Update servers blocked in hosts file."
Write-Host "Please restart your computer for changes to take effect."