# MDI-MDE-Monitor.ps1
# Monitors DNS queries, responses, and TCP connections for both MDI and MDE

param(
    [int]$DurationSeconds = 300,
    [string]$LogPath = "C:\Windows\Temp\mdi_mde_monitor.log"
)

# ============================================
# Configuration
# ============================================

$config = @{
    MDI = @{
        Domains = @(
            "atp.azure.com",
            "aatp.azure.com",
            "mdi.securitycenter.microsoft.com"
        )
        KnownIPs = [System.Collections.ArrayList]@(
            "20.43.130.88"
        )
        Processes = @(
            "Microsoft.Tri.Sensor",
            "Microsoft.Tri.Sensor.Updater"
        )
    }
    MDE = @{
        Domains = @(
            "winatp.com",
            "securitycenter.windows.com",
            "security.microsoft.com",
            "endpoint.security.microsoft.com"
        )
        KnownIPs = [System.Collections.ArrayList]@(
            "20.15.141.192",
            "20.44.10.122",
            "20.42.72.131"
        )
        Processes = @(
            "MsSense",
            "MsSenseS",
            "SenseIR",
            "SenseCncProxy"
        )
    }
}

$allDomains = $config.MDI.Domains + $config.MDE.Domains
$allProcesses = $config.MDI.Processes + $config.MDE.Processes

# ============================================
# Helper Functions
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO",
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    
    Write-Host $logEntry -ForegroundColor $Color
    $logEntry | Out-File $LogPath -Append
}

function Get-ProductName {
    param([string]$ProcessName, [string]$IP)
    
    if ($config.MDI.Processes -contains $ProcessName -or $config.MDI.KnownIPs -contains $IP) {
        return "MDI"
    }
    if ($config.MDE.Processes -contains $ProcessName -or $config.MDE.KnownIPs -contains $IP) {
        return "MDE"
    }
    return "UNKNOWN"
}

function Get-DomainProduct {
    param([string]$Domain)
    
    foreach ($d in $config.MDI.Domains) {
        if ($Domain -match [regex]::Escape($d)) { return "MDI" }
    }
    foreach ($d in $config.MDE.Domains) {
        if ($Domain -match [regex]::Escape($d)) { return "MDE" }
    }
    return "UNKNOWN"
}

# ============================================
# Main Monitoring
# ============================================

$startTime = Get-Date
$endTime = $startTime.AddSeconds($DurationSeconds)

# Create log header
"=" * 80 | Out-File $LogPath
"MDI/MDE Security Monitor" | Out-File $LogPath -Append
"Started: $startTime" | Out-File $LogPath -Append
"Duration: $DurationSeconds seconds" | Out-File $LogPath -Append
"=" * 80 | Out-File $LogPath -Append

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  MDI/MDE Security Monitor" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Duration: $DurationSeconds seconds" -ForegroundColor White
Write-Host "[*] Log file: $LogPath" -ForegroundColor White
Write-Host "[*] Monitoring for:" -ForegroundColor White
Write-Host "    - MDI processes: $($config.MDI.Processes -join ', ')" -ForegroundColor Yellow
Write-Host "    - MDE processes: $($config.MDE.Processes -join ', ')" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to stop early" -ForegroundColor Gray
Write-Host ""
Write-Host ("-" * 80) -ForegroundColor DarkGray
Write-Host ""

# Enable DNS debug logging
Write-Log "Enabling DNS debug logging..." "SETUP" "Gray"
$dnsLogPath = "C:\Windows\System32\dns\dns.log"
dnscmd /config /logLevel 0x8000F301 2>&1 | Out-Null
dnscmd /config /logFilePath $dnsLogPath 2>&1 | Out-Null
dnscmd /config /logFileMaxSize 50000000 2>&1 | Out-Null

# Tracking
$seenConnections = @{}
$seenDnsQueries = @{}
$dnsCache = @{}

$stats = @{
    MDI_DNS_Queries = 0
    MDI_DNS_Responses = 0
    MDI_TCP_Connections = 0
    MDE_DNS_Queries = 0
    MDE_DNS_Responses = 0
    MDE_TCP_Connections = 0
}

# ============================================
# Monitoring Loop
# ============================================

while ((Get-Date) -lt $endTime) {
    
    # --- Monitor DNS Server Log ---
    if (Test-Path $dnsLogPath) {
        try {
            $dnsContent = Get-Content $dnsLogPath -Tail 200 -ErrorAction SilentlyContinue
            
            foreach ($line in $dnsContent) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                
                foreach ($domain in $allDomains) {
                    if ($line -match [regex]::Escape($domain)) {
                        $lineHash = $line.GetHashCode().ToString()
                        
                        if (-not $seenDnsQueries.ContainsKey($lineHash)) {
                            $seenDnsQueries[$lineHash] = $true
                            $product = Get-DomainProduct -Domain $domain
                            $color = if ($product -eq "MDI") { "Yellow" } else { "Green" }
                            
                            # Parse DNS log entry
                            if ($line -match "PACKET") {
                                if ($line -match "Rcv") {
                                    Write-Log "DNS-QUERY: $domain (from client)" "$product" $color
                                    $stats["${product}_DNS_Queries"]++
                                }
                                elseif ($line -match "Snd") {
                                    # Extract response IP if present
                                    $responseIP = if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") { $matches[1] } else { "N/A" }
                                    Write-Log "DNS-RESPONSE: $domain -> $responseIP" "$product" $color
                                    $stats["${product}_DNS_Responses"]++
                                    $dnsCache[$domain] = $responseIP
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            # Silently continue
        }
    }
    
    # --- Monitor TCP Connections ---
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemotePort -eq 443 }
        
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.Name } else { "Unknown" }
            
            $key = "$($conn.RemoteAddress):$($conn.OwningProcess)"
            
            # Check if MDI/MDE related
            $isRelevantProcess = $allProcesses -contains $procName
            $isRelevantIP = ($config.MDI.KnownIPs -contains $conn.RemoteAddress) -or ($config.MDE.KnownIPs -contains $conn.RemoteAddress)
            
            if (($isRelevantProcess -or $isRelevantIP) -and -not $seenConnections.ContainsKey($key)) {
                $seenConnections[$key] = $true
                $product = Get-ProductName -ProcessName $procName -IP $conn.RemoteAddress
                $color = if ($product -eq "MDI") { "Yellow" } else { "Green" }
                
                Write-Log "TCP-CONNECTION: $($conn.RemoteAddress):$($conn.RemotePort) | Process: $procName (PID: $($conn.OwningProcess))" "$product" $color
                $stats["${product}_TCP_Connections"]++
                
                # Track new IPs
                if ($product -eq "MDI" -and $config.MDI.KnownIPs -notcontains $conn.RemoteAddress) {
                    $config.MDI.KnownIPs.Add($conn.RemoteAddress) | Out-Null
                }
                if ($product -eq "MDE" -and $config.MDE.KnownIPs -notcontains $conn.RemoteAddress) {
                    $config.MDE.KnownIPs.Add($conn.RemoteAddress) | Out-Null
                }
            }
        }
    } catch {
        # Silently continue
    }
    
    # --- Monitor Process Connections ---
    foreach ($procName in $allProcesses) {
        try {
            $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($proc) {
                $procConns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue |
                    Where-Object { 
                        $_.State -eq "Established" -and 
                        $_.RemoteAddress -notmatch "^(127\.|::1|fe80|0\.0\.0\.0)" -and
                        $_.RemotePort -eq 443
                    }
                
                foreach ($conn in $procConns) {
                    $key = "PROC:$procName`:$($conn.RemoteAddress)"
                    
                    if (-not $seenConnections.ContainsKey($key)) {
                        $seenConnections[$key] = $true
                        $product = Get-ProductName -ProcessName $procName -IP $conn.RemoteAddress
                        $color = if ($product -eq "MDI") { "Yellow" } else { "Green" }
                        
                        Write-Log "PROCESS-OUTBOUND: $procName -> $($conn.RemoteAddress):$($conn.RemotePort)" "$product" $color
                    }
                }
            }
        } catch {
            # Process may have exited
        }
    }
    
    # --- Real-time DNS Query Check (nslookup method) ---
    # Periodically verify DNS resolution
    $checkInterval = 30  # seconds
    $timeSinceStart = ((Get-Date) - $startTime).TotalSeconds
    
    if ([math]::Floor($timeSinceStart) % $checkInterval -eq 0 -and $timeSinceStart -gt 1) {
        foreach ($domain in @("redbear96sensorapi.atp.azure.com")) {
            try {
                $dnsResult = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
                if ($dnsResult) {
                    $resolvedIP = $dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1 -ExpandProperty IPAddress
                    if ($resolvedIP) {
                        $product = Get-DomainProduct -Domain $domain
                        $color = if ($resolvedIP -eq "127.0.0.1") { "Red" } else { "Cyan" }
                        Write-Log "DNS-CHECK: $domain resolves to $resolvedIP" "$product" $color
                    }
                }
            } catch {
                # DNS resolution failed
            }
        }
    }
    
    Start-Sleep -Seconds 1
}

# ============================================
# Cleanup and Summary
# ============================================

Write-Host ""
Write-Host ("-" * 80) -ForegroundColor DarkGray
Write-Log "Disabling DNS debug logging..." "SETUP" "Gray"
dnscmd /config /logLevel 0 2>&1 | Out-Null

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  Monitoring Summary" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""

Write-Host "  MDI (Microsoft Defender for Identity):" -ForegroundColor Yellow
Write-Host "    DNS Queries:     $($stats.MDI_DNS_Queries)"
Write-Host "    DNS Responses:   $($stats.MDI_DNS_Responses)"
Write-Host "    TCP Connections: $($stats.MDI_TCP_Connections)"
Write-Host ""

Write-Host "  MDE (Microsoft Defender for Endpoint):" -ForegroundColor Green
Write-Host "    DNS Queries:     $($stats.MDE_DNS_Queries)"
Write-Host "    DNS Responses:   $($stats.MDE_DNS_Responses)"
Write-Host "    TCP Connections: $($stats.MDE_TCP_Connections)"
Write-Host ""

Write-Host "  Discovered IPs:" -ForegroundColor Cyan
Write-Host "    MDI: $($config.MDI.KnownIPs -join ', ')"
Write-Host "    MDE: $($config.MDE.KnownIPs -join ', ')"
Write-Host ""

if ($dnsCache.Count -gt 0) {
    Write-Host "  DNS Resolution Cache:" -ForegroundColor Cyan
    foreach ($entry in $dnsCache.GetEnumerator()) {
        $status = if ($entry.Value -eq "127.0.0.1") { "[POISONED]" } else { "[OK]" }
        Write-Host "    $($entry.Key) -> $($entry.Value) $status"
    }
}

Write-Host ""
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  Log saved to: $LogPath" -ForegroundColor White
Write-Host ("=" * 80) -ForegroundColor Cyan

# Save summary to log
"" | Out-File $LogPath -Append
"=" * 80 | Out-File $LogPath -Append
"SUMMARY" | Out-File $LogPath -Append
"MDI: Queries=$($stats.MDI_DNS_Queries), Responses=$($stats.MDI_DNS_Responses), Connections=$($stats.MDI_TCP_Connections)" | Out-File $LogPath -Append
"MDE: Queries=$($stats.MDE_DNS_Queries), Responses=$($stats.MDE_DNS_Responses), Connections=$($stats.MDE_TCP_Connections)" | Out-File $LogPath -Append
"MDI IPs: $($config.MDI.KnownIPs -join ', ')" | Out-File $LogPath -Append
"MDE IPs: $($config.MDE.KnownIPs -join ', ')" | Out-File $LogPath -Append