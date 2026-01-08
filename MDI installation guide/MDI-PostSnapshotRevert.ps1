<#
.SYNOPSIS
    MDI Post-Snapshot Revert Configuration Script
    
.DESCRIPTION
    This script performs necessary configuration after reverting to a VM snapshot
    to ensure Microsoft Defender for Identity (MDI) functions correctly.
    
    Actions performed:
    1. Set timezone to UTC+7 (SE Asia Standard Time)
    2. Sync time with domain/NTP
    3. Disable Windows Firewall (all profiles)
    4. Restart MDI sensor services
    5. Verify sensor health and connectivity
    
.NOTES
    Author: Claude
    Version: 1.0
    Requires: Run as Administrator on Domain Controller with MDI sensor installed
#>

#Requires -RunAsAdministrator

# ============================================================================
# Configuration
# ============================================================================
$MDISensorApiEndpoint = "redbear96sensorapi.atp.azure.com"
$MDISensorApiPort = 443
$TimezoneName = "SE Asia Standard Time"  # UTC+7
$WaitTimeAfterServiceRestart = 30  # seconds

# ============================================================================
# Helper Functions
# ============================================================================

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# Main Script
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  MDI Post-Snapshot Revert Configuration Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check admin privileges
if (-not (Test-AdminPrivileges)) {
    Write-LogMessage "This script must be run as Administrator!" -Level "ERROR"
    exit 1
}

# ----------------------------------------------------------------------------
# Step 1: Set Timezone to UTC+7
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "[ STEP 1: Configure Timezone ]" -ForegroundColor Magenta
Write-Host "-" * 50

try {
    $currentTimezone = (Get-TimeZone).Id
    Write-LogMessage "Current timezone: $currentTimezone" -Level "INFO"
    
    if ($currentTimezone -ne $TimezoneName) {
        Set-TimeZone -Id $TimezoneName
        $newTimezone = (Get-TimeZone).Id
        Write-LogMessage "Timezone changed to: $newTimezone (UTC+7)" -Level "SUCCESS"
    } else {
        Write-LogMessage "Timezone already set to $TimezoneName (UTC+7)" -Level "SUCCESS"
    }
} catch {
    Write-LogMessage "Failed to set timezone: $_" -Level "ERROR"
}

# ----------------------------------------------------------------------------
# Step 2: Synchronize Time
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "[ STEP 2: Synchronize Time ]" -ForegroundColor Magenta
Write-Host "-" * 50

try {
    Write-LogMessage "Resyncing time with time source..." -Level "INFO"
    
    # Restart Windows Time service
    Restart-Service w32time -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    # Force time resync
    $resyncResult = w32tm /resync /force 2>&1
    Write-LogMessage "Time resync command executed" -Level "INFO"
    
    # Check time source status
    $timeStatus = w32tm /query /status 2>&1
    $sourceMatch = $timeStatus | Select-String -Pattern "Source:"
    if ($sourceMatch) {
        Write-LogMessage "Time source: $($sourceMatch -replace 'Source:\s*', '')" -Level "INFO"
    }
    
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
    Write-LogMessage "Current system time: $currentTime" -Level "SUCCESS"
    
} catch {
    Write-LogMessage "Time sync warning: $_" -Level "WARNING"
}

# ----------------------------------------------------------------------------
# Step 3: Disable Windows Firewall (All Profiles)
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "[ STEP 3: Disable Windows Firewall ]" -ForegroundColor Magenta
Write-Host "-" * 50

try {
    Write-LogMessage "Disabling Windows Firewall for all network profiles..." -Level "INFO"
    
    # Disable firewall for all profiles: Domain, Public, Private
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
    
    # Verify firewall status
    $firewallProfiles = Get-NetFirewallProfile -Profile Domain,Public,Private
    
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -eq $false) {
            Write-LogMessage "Firewall profile '$($profile.Name)': Disabled" -Level "SUCCESS"
        } else {
            Write-LogMessage "Firewall profile '$($profile.Name)': Still Enabled" -Level "WARNING"
        }
    }
    
} catch {
    Write-LogMessage "Failed to disable firewall: $_" -Level "ERROR"
}

# ----------------------------------------------------------------------------
# Step 4: Restart MDI Sensor Services
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "[ STEP 4: Restart MDI Sensor Services ]" -ForegroundColor Magenta
Write-Host "-" * 50

$mdiServices = @(
    @{ Name = "AATPSensorUpdater"; DisplayName = "Azure ATP Sensor Updater" },
    @{ Name = "AATPSensor"; DisplayName = "Azure ATP Sensor" }
)

foreach ($svc in $mdiServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        
        if ($null -eq $service) {
            Write-LogMessage "Service '$($svc.DisplayName)' not found - MDI may not be installed" -Level "WARNING"
            continue
        }
        
        Write-LogMessage "Stopping service: $($svc.DisplayName)..." -Level "INFO"
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        
        Write-LogMessage "Starting service: $($svc.DisplayName)..." -Level "INFO"
        Start-Service -Name $svc.Name -ErrorAction Stop
        
        $service = Get-Service -Name $svc.Name
        if ($service.Status -eq "Running") {
            Write-LogMessage "$($svc.DisplayName) is now Running" -Level "SUCCESS"
        } else {
            Write-LogMessage "$($svc.DisplayName) status: $($service.Status)" -Level "WARNING"
        }
        
    } catch {
        Write-LogMessage "Failed to restart $($svc.DisplayName): $_" -Level "ERROR"
    }
}

Write-LogMessage "Waiting $WaitTimeAfterServiceRestart seconds for services to stabilize..." -Level "INFO"
Start-Sleep -Seconds $WaitTimeAfterServiceRestart

# ----------------------------------------------------------------------------
# Step 5: Verify MDI Sensor Health
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "[ STEP 5: Verify MDI Sensor Health ]" -ForegroundColor Magenta
Write-Host "-" * 50

# 4.1 Check service status
Write-LogMessage "Checking MDI service status..." -Level "INFO"

$allServicesHealthy = $true
foreach ($svc in $mdiServices) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.Status -eq "Running") {
            Write-LogMessage "$($svc.DisplayName): Running" -Level "SUCCESS"
        } else {
            Write-LogMessage "$($svc.DisplayName): $($service.Status)" -Level "ERROR"
            $allServicesHealthy = $false
        }
    }
}

# 4.2 Test network connectivity to MDI cloud
Write-Host ""
Write-LogMessage "Testing connectivity to MDI cloud service..." -Level "INFO"

try {
    $tcpTest = Test-NetConnection -ComputerName $MDISensorApiEndpoint -Port $MDISensorApiPort -WarningAction SilentlyContinue
    
    if ($tcpTest.TcpTestSucceeded) {
        Write-LogMessage "Connection to $MDISensorApiEndpoint`:$MDISensorApiPort - SUCCESS" -Level "SUCCESS"
    } else {
        Write-LogMessage "Connection to $MDISensorApiEndpoint`:$MDISensorApiPort - FAILED" -Level "ERROR"
        $allServicesHealthy = $false
    }
} catch {
    Write-LogMessage "Network test failed: $_" -Level "ERROR"
    $allServicesHealthy = $false
}

# 4.3 Check DNS resolution
Write-Host ""
Write-LogMessage "Checking DNS resolution for MDI endpoint..." -Level "INFO"

try {
    $dnsResult = Resolve-DnsName -Name $MDISensorApiEndpoint -ErrorAction Stop
    Write-LogMessage "DNS resolution successful - Resolved to: $($dnsResult[0].IPAddress)" -Level "SUCCESS"
} catch {
    Write-LogMessage "DNS resolution failed for $MDISensorApiEndpoint" -Level "ERROR"
    $allServicesHealthy = $false
}

# 4.4 Check recent sensor logs for errors
Write-Host ""
Write-LogMessage "Checking MDI sensor logs for recent errors..." -Level "INFO"

$sensorLogPath = "C:\Program Files\Azure Advanced Threat Protection Sensor\*\Logs"
$logFiles = Get-ChildItem -Path $sensorLogPath -Filter "Microsoft.Tri.Sensor*.log" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1

if ($logFiles) {
    $recentErrors = Get-Content $logFiles.FullName -Tail 100 | 
                    Select-String -Pattern "Error|Exception|Failed" -SimpleMatch |
                    Select-Object -Last 5
    
    if ($recentErrors) {
        Write-LogMessage "Recent errors found in sensor log:" -Level "WARNING"
        foreach ($err in $recentErrors) {
            Write-Host "  $($err.Line)" -ForegroundColor Yellow
        }
    } else {
        Write-LogMessage "No recent errors found in sensor logs" -Level "SUCCESS"
    }
    
    Write-LogMessage "Log file location: $($logFiles.FullName)" -Level "INFO"
} else {
    Write-LogMessage "Could not locate MDI sensor logs" -Level "WARNING"
}

# 4.5 Display sensor version
Write-Host ""
$sensorExePath = Get-ChildItem -Path "C:\Program Files\Azure Advanced Threat Protection Sensor\*\Microsoft.Tri.Sensor.exe" -ErrorAction SilentlyContinue | 
                 Sort-Object LastWriteTime -Descending | 
                 Select-Object -First 1

if ($sensorExePath) {
    $version = (Get-Item $sensorExePath.FullName).VersionInfo.FileVersion
    Write-LogMessage "MDI Sensor Version: $version" -Level "INFO"
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$summary = @"

  Timezone:          $(Get-TimeZone | Select-Object -ExpandProperty Id)
  System Time:       $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
  
  Windows Firewall:
"@
Write-Host $summary

# Display firewall status
$firewallProfiles = Get-NetFirewallProfile -Profile Domain,Public,Private
foreach ($profile in $firewallProfiles) {
    $statusColor = if ($profile.Enabled -eq $false) { "Green" } else { "Red" }
    $statusText = if ($profile.Enabled -eq $false) { "Disabled" } else { "Enabled" }
    Write-Host "    - $($profile.Name): " -NoNewline
    Write-Host "$statusText" -ForegroundColor $statusColor
}

Write-Host ""
Write-Host "  MDI Services:"

foreach ($svc in $mdiServices) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $statusColor = if ($service.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "    - $($svc.DisplayName): " -NoNewline
        Write-Host "$($service.Status)" -ForegroundColor $statusColor
    }
}

Write-Host ""
Write-Host "  Cloud Connectivity: " -NoNewline
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "Connected" -ForegroundColor Green
} else {
    Write-Host "Failed" -ForegroundColor Red
}

Write-Host ""
if ($allServicesHealthy) {
    Write-Host "  Overall Status: " -NoNewline
    Write-Host "HEALTHY" -ForegroundColor Green
    Write-Host ""
    Write-LogMessage "MDI sensor is ready. Wait 1-2 minutes before testing detections." -Level "SUCCESS"
} else {
    Write-Host "  Overall Status: " -NoNewline
    Write-Host "ISSUES DETECTED" -ForegroundColor Red
    Write-Host ""
    Write-LogMessage "Please review the errors above and check MDI portal for health issues." -Level "WARNING"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Check MDI portal: Settings -> Identities -> Sensors" -ForegroundColor White
Write-Host "  2. Verify sensor shows 'Running' and 'Healthy'" -ForegroundColor White
Write-Host "  3. Wait 1-2 minutes before running DCSync test" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
