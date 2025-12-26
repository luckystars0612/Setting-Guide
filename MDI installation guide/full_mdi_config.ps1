#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
    Complete MDI (Microsoft Defender for Identity) Pre-Installation Configuration Script
.DESCRIPTION
    This script configures all MDI prerequisites based on official Microsoft documentation:
    - Directory Service Account (DSA) Setup (gMSA or regular account)
    - Deleted Objects Container Permissions
    - Network Name Resolution (NNR) Port Validation
    - SAM-R Configuration for Lateral Movement Path Detection
    - Object Auditing (Domain SACL)
    - Advanced Auditing (Security audit policies)
    - NTLM Auditing (Registry settings)
    - Power Settings (High Performance mode)
    - Time Synchronization Check
    - Connectivity Validation
.PARAMETER Domain
    The domain FQDN to configure. Defaults to current user's domain.
.PARAMETER DSAName
    Name of the Directory Service Account (gMSA or regular account)
.PARAMETER DSAType
    Type of DSA: 'gMSA' (recommended) or 'Regular'
.PARAMETER DSAGroupName
    Security group name for gMSA (required for Deleted Objects permissions)
.PARAMETER SkipDSACreation
    Skip DSA account creation (use if DSA already exists)
.PARAMETER ValidateOnly
    Only validate current configuration without making changes
.NOTES
    Run this script as Administrator on your Domain Controller
    Version: 3.0
    Based on:
    - https://learn.microsoft.com/en-us/defender-for-identity/nnr-policy
    - https://learn.microsoft.com/en-us/defender-for-identity/deploy/remote-calls-sam
    - https://learn.microsoft.com/en-us/defender-for-identity/deploy/directory-service-accounts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Domain = $env:USERDNSDOMAIN,
    
    [Parameter(Mandatory = $false)]
    [string]$DSAName = "mdiSvc01",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('gMSA', 'Regular')]
    [string]$DSAType = 'gMSA',
    
    [Parameter(Mandatory = $false)]
    [string]$DSAGroupName = "mdiSvc01Group",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipDSACreation,
    
    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly
)

# Script variables
$script:ErrorCount = 0
$script:WarningCount = 0
$script:SuccessCount = 0

#region Helper Functions
function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('OK', 'ERROR', 'WARN', 'INFO', 'SKIP')]
        [string]$Status
    )
    
    switch ($Status) {
        'OK'    { Write-Host "  [OK] $Message" -ForegroundColor Green; $script:SuccessCount++ }
        'ERROR' { Write-Host "  [ERROR] $Message" -ForegroundColor Red; $script:ErrorCount++ }
        'WARN'  { Write-Host "  [WARN] $Message" -ForegroundColor Yellow; $script:WarningCount++ }
        'INFO'  { Write-Host "  [INFO] $Message" -ForegroundColor Cyan }
        'SKIP'  { Write-Host "  [SKIP] $Message" -ForegroundColor Gray }
    }
}

function Write-SectionHeader {
    param([string]$Title, [int]$Number, [int]$Total)
    Write-Host ""
    Write-Host "[$Number/$Total] $Title" -ForegroundColor Yellow
}

function Test-PortConnectivity {
    param(
        [string]$ComputerName,
        [int]$Port,
        [string]$Protocol = 'TCP'
    )
    
    try {
        if ($Protocol -eq 'TCP') {
            $connection = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningAction SilentlyContinue
            return $connection.TcpTestSucceeded
        }
        else {
            # UDP test using socket
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Connect($ComputerName, $Port)
            $udpClient.Close()
            return $true
        }
    }
    catch {
        return $false
    }
}
#endregion

#region Banner
Clear-Host
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|     Microsoft Defender for Identity - Configuration Script       |" -ForegroundColor Cyan
Write-Host "|                         Version 3.0                              |" -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|  Domain: $($Domain.PadRight(54))|" -ForegroundColor Cyan
Write-Host "|  DSA Name: $($DSAName.PadRight(52))|" -ForegroundColor Cyan
Write-Host "|  DSA Type: $($DSAType.PadRight(52))|" -ForegroundColor Cyan
if ($ValidateOnly) { $modeText = 'Validation Only' } else { $modeText = 'Configure' }
Write-Host ("|  Mode: " + $modeText.PadRight(56) + "|") -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host ""
#endregion

$totalSteps = 10

#region 1. Prerequisites Check
Write-SectionHeader -Title "Checking Prerequisites..." -Number 1 -Total $totalSteps

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-StatusMessage -Message "ActiveDirectory module loaded" -Status OK
}
catch {
    Write-StatusMessage -Message "ActiveDirectory module not available: $_" -Status ERROR
    exit 1
}

# Get domain information
try {
    $domainInfo = Get-ADDomain -Server $Domain -ErrorAction Stop
    $domainDN = $domainInfo.DistinguishedName
    $domainNetBIOS = $domainInfo.NetBIOSName
    Write-StatusMessage -Message "Connected to domain: $domainDN" -Status OK
}
catch {
    Write-StatusMessage -Message "Failed to connect to domain: $_" -Status ERROR
    exit 1
}

# Check if running on DC
$computerRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
if ($computerRole -ge 4) {
    Write-StatusMessage -Message "Running on Domain Controller" -Status OK
}
else {
    Write-StatusMessage -Message ('Not running on a Domain Controller (Role ' + $computerRole + ')') -Status WARN
}
#endregion

#region 2. Time Synchronization Check
Write-SectionHeader -Title "Checking Time Synchronization..." -Number 2 -Total $totalSteps

try {
    $w32tmOutput = & w32tm /query /status 2>&1
    if ($w32tmOutput -match "Leap Indicator: 0") {
        Write-StatusMessage -Message "Time synchronization is healthy" -Status OK
    }
    else {
        Write-StatusMessage -Message "Time synchronization may have issues - verify manually" -Status WARN
    }
    
    # Check time offset
    $timeOffset = & w32tm /stripchart /computer:$Domain /samples:1 /dataonly 2>&1
    if ($timeOffset -match "(\d+\.\d+)s") {
        $offset = [math]::Abs([double]$matches[1])
        if ($offset -lt 300) {  # Less than 5 minutes (300 seconds)
            $msg = 'Time offset is within acceptable range ({0}s, limit 300s)' -f $offset
            Write-StatusMessage -Message $msg -Status OK
        }
        else {
            $msg = 'Time offset exceeds 5 minutes ({0}s) - MDI requires under 5 min sync' -f $offset
            Write-StatusMessage -Message $msg -Status ERROR
        }
    }
}
catch {
    Write-StatusMessage -Message "Could not verify time synchronization: $_" -Status WARN
}
#endregion

#region 3. Directory Service Account (DSA) Setup
Write-SectionHeader -Title "Configuring Directory Service Account (DSA)..." -Number 3 -Total $totalSteps

if ($SkipDSACreation) {
    Write-StatusMessage -Message "DSA creation skipped (using existing account)" -Status SKIP
}
elseif ($ValidateOnly) {
    # Just check if DSA exists
    if ($DSAType -eq 'gMSA') {
        $existingGMSA = Get-ADServiceAccount -Filter "Name -eq '$DSAName'" -ErrorAction SilentlyContinue
        if ($existingGMSA) {
            Write-StatusMessage -Message "gMSA '$DSAName' exists" -Status OK
        }
        else {
            Write-StatusMessage -Message "gMSA '$DSAName' not found" -Status WARN
        }
    }
    else {
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$DSAName'" -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-StatusMessage -Message "User account '$DSAName' exists" -Status OK
        }
        else {
            Write-StatusMessage -Message "User account '$DSAName' not found" -Status WARN
        }
    }
}
else {
    if ($DSAType -eq 'gMSA') {
        # Check if KDS Root Key exists
        $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
        if (-not $kdsKey) {
            Write-StatusMessage -Message "Creating KDS Root Key (required for gMSA)..." -Status INFO
            try {
                # For production, use: Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                # For lab/testing (immediate): Add-KdsRootKey -EffectiveImmediately
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
                Write-StatusMessage -Message "KDS Root Key created (effective in 10 hours for replication)" -Status OK
            }
            catch {
                Write-StatusMessage -Message "Failed to create KDS Root Key: $_" -Status ERROR
            }
        }
        else {
            Write-StatusMessage -Message "KDS Root Key already exists" -Status OK
        }
        
        # Create gMSA
        $existingGMSA = Get-ADServiceAccount -Filter "Name -eq '$DSAName'" -ErrorAction SilentlyContinue
        if (-not $existingGMSA) {
            try {
                # Get all DCs to allow gMSA password retrieval
                $domainControllers = Get-ADGroupMember -Identity "Domain Controllers" -ErrorAction Stop
                
                New-ADServiceAccount -Name $DSAName `
                    -DNSHostName "$DSAName.$Domain" `
                    -PrincipalsAllowedToRetrieveManagedPassword $domainControllers `
                    -ErrorAction Stop
                
                Write-StatusMessage -Message "gMSA '$DSAName' created successfully" -Status OK
            }
            catch {
                Write-StatusMessage -Message "Failed to create gMSA: $_" -Status ERROR
            }
        }
        else {
            Write-StatusMessage -Message "gMSA '$DSAName' already exists" -Status OK
        }
        
        # Create security group for gMSA (required for Deleted Objects permissions)
        $existingGroup = Get-ADGroup -Filter "Name -eq '$DSAGroupName'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            try {
                New-ADGroup -Name $DSAGroupName `
                    -SamAccountName $DSAGroupName `
                    -DisplayName $DSAGroupName `
                    -GroupCategory Security `
                    -GroupScope Universal `
                    -Description "Members allowed to read Deleted Objects container for MDI" `
                    -ErrorAction Stop
                
                # Add gMSA to the group
                Add-ADGroupMember -Identity $DSAGroupName -Members "$DSAName$" -ErrorAction Stop
                Write-StatusMessage -Message "Security group '$DSAGroupName' created and gMSA added" -Status OK
            }
            catch {
                Write-StatusMessage -Message "Failed to create security group: $_" -Status ERROR
            }
        }
        else {
            Write-StatusMessage -Message "Security group '$DSAGroupName' already exists" -Status OK
            # Ensure gMSA is a member
            try {
                $members = Get-ADGroupMember -Identity $DSAGroupName -ErrorAction SilentlyContinue
                if ($members.SamAccountName -notcontains "$DSAName$") {
                    Add-ADGroupMember -Identity $DSAGroupName -Members "$DSAName$" -ErrorAction Stop
                    Write-StatusMessage -Message "Added gMSA to security group" -Status OK
                }
            }
            catch {
                Write-StatusMessage -Message "Could not verify/add gMSA to group: $_" -Status WARN
            }
        }
    }
    else {
        # Create regular user account
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$DSAName'" -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            Write-StatusMessage -Message "Regular user account creation requires manual password setup" -Status INFO
            Write-Host "    Run the following command to create the account:" -ForegroundColor White
            Write-Host "    New-ADUser -Name '$DSAName' -SamAccountName '$DSAName' -UserPrincipalName '$DSAName@$Domain' -Enabled `$true -AccountPassword (Read-Host -AsSecureString 'Password') -PasswordNeverExpires `$true" -ForegroundColor Gray
        }
        else {
            Write-StatusMessage -Message "User account '$DSAName' already exists" -Status OK
        }
    }
}
#endregion

#region 4. Deleted Objects Container Permissions
Write-SectionHeader -Title "Configuring Deleted Objects Container Permissions..." -Number 4 -Total $totalSteps

if ($ValidateOnly) {
    Write-StatusMessage -Message "Validation mode - skipping Deleted Objects configuration" -Status SKIP
}
else {
    try {
        # Determine the identity to grant permissions
        $identity = if ($DSAType -eq 'gMSA') { $DSAGroupName } else { $DSAName }
        
        # Get the deleted objects container's distinguished name
        $deletedObjectsDN = "CN=Deleted Objects,$domainDN"
        
        # Take ownership and grant permissions using dsacls
        Write-StatusMessage -Message "Configuring permissions on Deleted Objects container..." -Status INFO
        
        # Take ownership
        $takeOwnership = & dsacls.exe $deletedObjectsDN /takeOwnership 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-StatusMessage -Message "Ownership taken on Deleted Objects container" -Status OK
        }
        else {
            Write-StatusMessage -Message "Could not take ownership (may already be configured): $takeOwnership" -Status WARN
        }
        
        # Grant List Contents and Read Property permissions (LCRP)
        $grantResult = & dsacls.exe $deletedObjectsDN /G "${domainNetBIOS}\${identity}:LCRP" 2>&1
        if ($LASTEXITCODE -eq 0 -or $grantResult -match "successfully") {
            Write-StatusMessage -Message "Granted LCRP permissions to '$identity' on Deleted Objects" -Status OK
        }
        else {
            Write-StatusMessage -Message "Could not grant permissions: $grantResult" -Status ERROR
        }
    }
    catch {
        Write-StatusMessage -Message "Failed to configure Deleted Objects permissions: $_" -Status ERROR
    }
}
#endregion

#region 5. Network Name Resolution (NNR) Port Validation and Firewall Configuration
Write-SectionHeader -Title "Configuring NNR Ports and Firewall Rules..." -Number 5 -Total $totalSteps

Write-StatusMessage -Message "NNR is required for correlating IP addresses to computer names" -Status INFO

# Define required MDI ports
$mdiPorts = @(
    @{Port = 135; Protocol = 'TCP'; Name = 'MDI-NNR-RPC'; Description = 'MDI NNR - NTLM over RPC (Primary)'},
    @{Port = 137; Protocol = 'UDP'; Name = 'MDI-NNR-NetBIOS'; Description = 'MDI NNR - NetBIOS (Primary)'},
    @{Port = 3389; Protocol = 'TCP'; Name = 'MDI-NNR-RDP'; Description = 'MDI NNR - RDP (Primary)'},
    @{Port = 53; Protocol = 'UDP'; Name = 'MDI-NNR-DNS'; Description = 'MDI NNR - DNS (Secondary)'},
    @{Port = 53; Protocol = 'TCP'; Name = 'MDI-NNR-DNS-TCP'; Description = 'MDI NNR - DNS TCP (Secondary)'},
    @{Port = 445; Protocol = 'TCP'; Name = 'MDI-SAM-R'; Description = 'MDI SAM-R - Lateral Movement Path Detection'}
)

# Function to create firewall rule
function New-MDIFirewallRule {
    param(
        [int]$Port,
        [string]$Protocol,
        [string]$Name,
        [string]$Description
    )
    
    try {
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            # Enable if disabled
            if ($existingRule.Enabled -eq 'False') {
                Enable-NetFirewallRule -DisplayName $Name
                Write-StatusMessage -Message "Enabled existing firewall rule: $Name" -Status OK
            }
            else {
                Write-StatusMessage -Message "Firewall rule already exists and enabled: $Name" -Status OK
            }
        }
        else {
            # Create new inbound rule
            New-NetFirewallRule -DisplayName $Name `
                -Description $Description `
                -Direction Inbound `
                -Protocol $Protocol `
                -LocalPort $Port `
                -Action Allow `
                -Enabled True `
                -Profile Domain,Private `
                -ErrorAction Stop | Out-Null
            
            Write-StatusMessage -Message "Created firewall rule: $Name ($Protocol $Port)" -Status OK
        }
        return $true
    }
    catch {
        Write-StatusMessage -Message "Failed to create firewall rule $Name : $_" -Status ERROR
        return $false
    }
}

# Create/verify firewall rules for all MDI ports
Write-StatusMessage -Message "Configuring Windows Firewall rules for MDI..." -Status INFO

foreach ($portConfig in $mdiPorts) {
    New-MDIFirewallRule -Port $portConfig.Port -Protocol $portConfig.Protocol -Name $portConfig.Name -Description $portConfig.Description
}

# Test connectivity after firewall configuration
Write-Host ""
Write-StatusMessage -Message "Testing port connectivity..." -Status INFO

try {
    $testComputers = Get-ADComputer -Filter * -ResultSetSize 3 -ErrorAction Stop | Select-Object -ExpandProperty DNSHostName
    
    if ($testComputers) {
        $testTarget = $testComputers | Select-Object -First 1
        
        # Test TCP 135 (NTLM over RPC)
        $port135 = Test-PortConnectivity -ComputerName $testTarget -Port 135 -Protocol TCP
        if ($port135) {
            Write-StatusMessage -Message "TCP 135 (NTLM over RPC) - Open to $testTarget" -Status OK
        }
        else {
            Write-StatusMessage -Message "TCP 135 (NTLM over RPC) - May require remote host firewall config" -Status WARN
        }
        
        # Test TCP 445 (SAM-R)
        $port445 = Test-PortConnectivity -ComputerName $testTarget -Port 445 -Protocol TCP
        if ($port445) {
            Write-StatusMessage -Message "TCP 445 (SAM-R) - Open to $testTarget" -Status OK
        }
        else {
            Write-StatusMessage -Message "TCP 445 (SAM-R) - May require remote host firewall config" -Status WARN
        }
        
        # Test TCP 3389 (RDP)
        $port3389 = Test-PortConnectivity -ComputerName $testTarget -Port 3389 -Protocol TCP
        if ($port3389) {
            Write-StatusMessage -Message "TCP 3389 (RDP) - Open to $testTarget" -Status OK
        }
        else {
            Write-StatusMessage -Message "TCP 3389 (RDP) - May require remote host firewall config" -Status INFO
        }
        
        # Test DNS
        $dnsServer = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object -First 1).ServerAddresses[0]
        if ($dnsServer) {
            $port53 = Test-PortConnectivity -ComputerName $dnsServer -Port 53 -Protocol TCP
            if ($port53) {
                Write-StatusMessage -Message "TCP/UDP 53 (DNS) - Available via $dnsServer" -Status OK
            }
            else {
                Write-StatusMessage -Message "DNS connectivity check inconclusive" -Status INFO
            }
        }
    }
    else {
        Write-StatusMessage -Message "No computers found to test connectivity" -Status WARN
    }
}
catch {
    Write-StatusMessage -Message "Could not perform connectivity test: $_" -Status WARN
}

Write-Host ""
Write-Host "    MDI Required Ports Summary:" -ForegroundColor White
Write-Host "    [+] TCP 135 - NTLM over RPC (Primary NNR)" -ForegroundColor Gray
Write-Host "    [+] UDP 137 - NetBIOS (Primary NNR)" -ForegroundColor Gray
Write-Host "    [+] TCP 3389 - RDP (Primary NNR)" -ForegroundColor Gray
Write-Host "    [+] TCP/UDP 53 - DNS (Secondary NNR)" -ForegroundColor Gray
Write-Host "    [+] TCP 445 - SAM-R (Lateral Movement Paths)" -ForegroundColor Gray
Write-Host ""
#endregion

#region 6. SAM-R Configuration
Write-SectionHeader -Title "Configuring SAM-R for Lateral Movement Paths..." -Number 6 -Total $totalSteps

Write-StatusMessage -Message "Configuring SAM-R permissions for MDI lateral movement path detection" -Status INFO

if (-not $ValidateOnly) {
    try {
        # Get the DSA SID
        $dsaAccount = $null
        if ($DSAType -eq 'gMSA') {
            $dsaAccount = Get-ADServiceAccount -Identity $DSAName -ErrorAction SilentlyContinue
        }
        if (-not $dsaAccount) {
            $dsaAccount = Get-ADUser -Identity $DSAName -ErrorAction SilentlyContinue
        }
        
        if ($dsaAccount) {
            $dsaSID = $dsaAccount.SID.Value
            
            # Build the SDDL string
            # O:BAG:BAD:(A;;RC;;;BA) = Built-in Administrators
            # (A;;RC;;;$dsaSID) = DSA account
            $sddl = 'O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;' + $dsaSID + ')'
            
            Write-StatusMessage -Message "Generated SDDL for DSA account: $DSAName" -Status OK
            
            # Try to configure via registry (local policy)
            $samrRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            $samrRegName = 'RestrictRemoteSAM'
            
            try {
                Set-ItemProperty -Path $samrRegPath -Name $samrRegName -Value $sddl -Type String -Force -ErrorAction Stop
                Write-StatusMessage -Message "Configured local SAM-R policy via registry" -Status OK
            }
            catch {
                Write-StatusMessage -Message "Could not set registry, will need GPO configuration" -Status WARN
            }
            
            Write-Host ""
            Write-Host "    SAM-R Configuration Details:" -ForegroundColor White
            Write-Host "    SDDL: $sddl" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "    For domain-wide deployment via Group Policy:" -ForegroundColor Yellow
            Write-Host "    1. Open Group Policy Management" -ForegroundColor Gray
            Write-Host "    2. Create/Edit a GPO linked to workstations OU" -ForegroundColor Gray
            Write-Host "    3. Navigate to: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options" -ForegroundColor Gray
            Write-Host "    4. Configure: Network access - Restrict clients allowed to make remote calls to SAM" -ForegroundColor Gray
            Write-Host "    5. Set the SDDL value shown above" -ForegroundColor Gray
            Write-Host "    6. Apply GPO to all workstations and member servers (NOT domain controllers)" -ForegroundColor Gray
            Write-Host ""
        }
        else {
            Write-StatusMessage -Message "DSA account '$DSAName' not found - SAM-R configuration skipped" -Status WARN
            Write-StatusMessage -Message "Create DSA first, then re-run this script" -Status INFO
        }
    }
    catch {
        Write-StatusMessage -Message "Could not configure SAM-R: $_" -Status ERROR
    }
}
else {
    # Validation mode - check current configuration
    try {
        $samrRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $samrRegName = 'RestrictRemoteSAM'
        $currentValue = Get-ItemProperty -Path $samrRegPath -Name $samrRegName -ErrorAction SilentlyContinue
        
        if ($currentValue) {
            Write-StatusMessage -Message "SAM-R policy is configured: $($currentValue.RestrictRemoteSAM)" -Status OK
        }
        else {
            Write-StatusMessage -Message "SAM-R policy is not configured locally" -Status WARN
        }
    }
    catch {
        Write-StatusMessage -Message "Could not check SAM-R configuration: $_" -Status WARN
    }
}
#endregion

#region 7. Object Auditing (Domain SACL)
Write-SectionHeader -Title "Configuring Object Auditing (Domain SACL)..." -Number 7 -Total $totalSteps

if ($ValidateOnly) {
    Write-StatusMessage -Message "Validation mode - checking current SACL configuration" -Status INFO
    try {
        $acl = Get-Acl "AD:\$domainDN" -Audit
        $auditRules = $acl.Audit
        if ($auditRules.Count -gt 0) {
            Write-StatusMessage -Message "Found $($auditRules.Count) audit rules configured" -Status OK
        }
        else {
            Write-StatusMessage -Message "No audit rules found on domain root" -Status WARN
        }
    }
    catch {
        Write-StatusMessage -Message "Could not check SACL: $_" -Status WARN
    }
}
else {
    try {
        # Define the required SACL entries for MDI
        # These GUIDs represent the object types that MDI needs to audit
        $objectAuditingRules = @(
            @{InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"; Description = "Descendant User Objects"},
            @{InheritedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2"; Description = "Descendant Group Objects"},
            @{InheritedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2"; Description = "Descendant Computer Objects"},
            @{InheritedObjectType = "ce206244-5827-4a86-ba1c-1c0c386c1b64"; Description = "Descendant msDS-ManagedServiceAccount Objects"},
            @{InheritedObjectType = "7b8b558a-93a5-4af7-adca-c017e67f1057"; Description = "Descendant msDS-GroupManagedServiceAccount Objects"}
        )
        
        # Get the current ACL
        $acl = Get-Acl "AD:\$domainDN" -Audit
        
        # Everyone SID (S-1-1-0)
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        
        foreach ($rule in $objectAuditingRules) {
            try {
                # Create audit rule for each object type
                $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                    $everyoneSid,
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                    [System.Security.AccessControl.AuditFlags]::Success,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
                    [guid]$rule.InheritedObjectType
                )
                $acl.AddAuditRule($auditRule)
                Write-StatusMessage -Message "Added audit rule for $($rule.Description)" -Status OK
            }
            catch {
                Write-StatusMessage -Message "Could not add rule for $($rule.Description): $_" -Status WARN
            }
        }
        
        # Apply the ACL
        Set-Acl "AD:\$domainDN" $acl
        Write-StatusMessage -Message "Object Auditing SACL applied successfully" -Status OK
    }
    catch {
        Write-StatusMessage -Message "Failed to configure Object Auditing: $_" -Status ERROR
    }
}
#endregion

#region 8. Advanced Auditing Policies
Write-SectionHeader -Title "Configuring Advanced Auditing Policies..." -Number 8 -Total $totalSteps

# MDI required audit policies
$auditPolicies = @(
    @{Subcategory = "Security System Extension"; Success = $true; Failure = $true},
    @{Subcategory = "Distribution Group Management"; Success = $true; Failure = $true},
    @{Subcategory = "Security Group Management"; Success = $true; Failure = $true},
    @{Subcategory = "Computer Account Management"; Success = $true; Failure = $true},
    @{Subcategory = "User Account Management"; Success = $true; Failure = $true},
    @{Subcategory = "Directory Service Access"; Success = $true; Failure = $true},
    @{Subcategory = "Directory Service Changes"; Success = $true; Failure = $true},
    @{Subcategory = "Credential Validation"; Success = $true; Failure = $true},
    @{Subcategory = "Other Logon/Logoff Events"; Success = $true; Failure = $true},
    @{Subcategory = "Kerberos Authentication Service"; Success = $true; Failure = $true},
    @{Subcategory = "Kerberos Service Ticket Operations"; Success = $true; Failure = $true}
)

if ($ValidateOnly) {
    Write-StatusMessage -Message "Checking current audit policy configuration..." -Status INFO
    foreach ($policy in $auditPolicies) {
        $currentPolicy = & auditpol /get /subcategory:"$($policy.Subcategory)" 2>&1
        if ($currentPolicy -match "Success and Failure|Success|Failure") {
            Write-StatusMessage -Message "$($policy.Subcategory) - Configured" -Status OK
        }
        else {
            Write-StatusMessage -Message "$($policy.Subcategory) - Not configured" -Status WARN
        }
    }
}
else {
    foreach ($policy in $auditPolicies) {
        try {
            $successFlag = if ($policy.Success) { "/success:enable" } else { "/success:disable" }
            $failureFlag = if ($policy.Failure) { "/failure:enable" } else { "/failure:disable" }
            
            $result = & auditpol /set /subcategory:"$($policy.Subcategory)" $successFlag $failureFlag 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-StatusMessage -Message "$($policy.Subcategory)" -Status OK
            }
            else {
                Write-StatusMessage -Message "$($policy.Subcategory): $result" -Status ERROR
            }
        }
        catch {
            Write-StatusMessage -Message "$($policy.Subcategory): $_" -Status ERROR
        }
    }
}
#endregion

#region 9. NTLM Auditing
Write-SectionHeader -Title "Configuring NTLM Auditing..." -Number 9 -Total $totalSteps

# NTLM audit settings required for MDI
$ntlmSettings = @(
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Name = "AuditReceivingNTLMTraffic"
        Value = 2
        Description = "Audit Receiving NTLM Traffic (Enable auditing for all accounts)"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        Name = "RestrictSendingNTLMTraffic"
        Value = 1
        Description = "Restrict Sending NTLM Traffic (Audit all)"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        Name = "AuditNTLMInDomain"
        Value = 7
        Description = "Audit NTLM In Domain (Enable all)"
    }
)

if ($ValidateOnly) {
    foreach ($setting in $ntlmSettings) {
        try {
            $currentValue = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue
            if ($currentValue.$($setting.Name) -eq $setting.Value) {
                Write-StatusMessage -Message "$($setting.Description) = $($setting.Value)" -Status OK
            }
            else {
                Write-StatusMessage -Message "$($setting.Description) - Current: $($currentValue.$($setting.Name)), Required: $($setting.Value)" -Status WARN
            }
        }
        catch {
            Write-StatusMessage -Message "$($setting.Description) - Not configured" -Status WARN
        }
    }
}
else {
    foreach ($setting in $ntlmSettings) {
        try {
            # Ensure the registry path exists
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord -Force
            Write-StatusMessage -Message "$($setting.Description) = $($setting.Value)" -Status OK
        }
        catch {
            Write-StatusMessage -Message "$($setting.Description): $_" -Status ERROR
        }
    }
}
#endregion

#region 10. Power Settings and Final Configuration
Write-SectionHeader -Title "Configuring Power Settings and Final Steps..." -Number 10 -Total $totalSteps

if ($ValidateOnly) {
    # Check current power plan
    $currentPlan = & powercfg /getactivescheme 2>&1
    if ($currentPlan -match "High performance|8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c") {
        Write-StatusMessage -Message "High Performance power plan is active" -Status OK
    }
    else {
        Write-StatusMessage -Message "High Performance power plan is NOT active" -Status WARN
    }
}
else {
    try {
        # Set High Performance power plan
        $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        
        $powerSchemes = & powercfg /list 2>&1
        if ($powerSchemes -match $highPerfGuid) {
            & powercfg /setactive $highPerfGuid 2>&1 | Out-Null
            Write-StatusMessage -Message "High Performance power plan activated" -Status OK
        }
        else {
            & powercfg /duplicatescheme $highPerfGuid 2>&1 | Out-Null
            & powercfg /setactive $highPerfGuid 2>&1 | Out-Null
            Write-StatusMessage -Message "High Performance power plan created and activated" -Status OK
        }
        
        # Disable timeouts
        & powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
        & powercfg /change standby-timeout-dc 0 2>&1 | Out-Null
        & powercfg /change hibernate-timeout-ac 0 2>&1 | Out-Null
        & powercfg /change hibernate-timeout-dc 0 2>&1 | Out-Null
        & powercfg /change monitor-timeout-ac 0 2>&1 | Out-Null
        Write-StatusMessage -Message "Power timeouts disabled" -Status OK
    }
    catch {
        Write-StatusMessage -Message "Failed to configure Power Settings: $_" -Status ERROR
    }
}

# Check MDI cloud connectivity
Write-StatusMessage -Message "Checking MDI cloud service connectivity..." -Status INFO
try {
    $mdiEndpoints = @(
        "*.atp.azure.com"
    )
    
    # Test general internet connectivity first
    $internetTest = Test-NetConnection -ComputerName "www.microsoft.com" -Port 443 -WarningAction SilentlyContinue
    if ($internetTest.TcpTestSucceeded) {
        Write-StatusMessage -Message "Internet connectivity (HTTPS) available" -Status OK
    }
    else {
        Write-StatusMessage -Message "Internet connectivity may be limited" -Status WARN
    }
}
catch {
    Write-StatusMessage -Message "Could not verify connectivity: $_" -Status WARN
}

# Update Group Policy
if (-not $ValidateOnly) {
    Write-StatusMessage -Message "Forcing Group Policy update..." -Status INFO
    try {
        $gpResult = & gpupdate /force 2>&1
        Write-StatusMessage -Message "Group Policy updated" -Status OK
    }
    catch {
        Write-StatusMessage -Message "Group Policy update had issues: $_" -Status WARN
    }
}

# Restart MDI Sensor if present
if (-not $ValidateOnly) {
    try {
        $sensorService = Get-Service -Name "AATPSensor" -ErrorAction SilentlyContinue
        if ($sensorService) {
            Restart-Service -Name "AATPSensor" -Force -ErrorAction Stop
            Write-StatusMessage -Message "MDI Sensor service (AATPSensor) restarted" -Status OK
        }
        else {
            $sensorService = Get-Service -DisplayName "*Azure Advanced Threat Protection*" -ErrorAction SilentlyContinue
            if ($sensorService) {
                Restart-Service -Name $sensorService.Name -Force -ErrorAction Stop
                Write-StatusMessage -Message "MDI Sensor service restarted" -Status OK
            }
            else {
                Write-StatusMessage -Message "MDI Sensor not installed yet - will apply settings when installed" -Status INFO
            }
        }
    }
    catch {
        Write-StatusMessage -Message "Could not restart MDI Sensor service: $_" -Status WARN
    }
}
#endregion

#region Summary Report
Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|                    Configuration Summary                          |" -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|  Success: $($script:SuccessCount.ToString().PadRight(56))|" -ForegroundColor Green
Write-Host "|  Warnings: $($script:WarningCount.ToString().PadRight(55))|" -ForegroundColor Yellow
if ($script:ErrorCount -gt 0) { $errorColor = 'Red' } else { $errorColor = 'Green' }
Write-Host "|  Errors: $($script:ErrorCount.ToString().PadRight(57))|" -ForegroundColor $errorColor
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host ""

if ($ValidateOnly) {
    Write-Host "Validation Complete - No changes were made" -ForegroundColor Cyan
    Write-Host ""
}
else {
    Write-Host "Configuration Applied - Summary of Changes:" -ForegroundColor Yellow
    if ($SkipDSACreation) { $dsaStatus = 'Skipped' } else { $dsaStatus = 'Configured' }
    Write-Host "  [+] Directory Service Account: $dsaStatus"
    Write-Host "  [+] Deleted Objects Permissions: Configured"
    Write-Host "  [+] Firewall Rules: Configured (NNR + SAM-R ports)"
    Write-Host "  [+] Object Auditing (SACL): Configured"
    Write-Host "  [+] Advanced Audit Policies: Configured"
    Write-Host "  [+] NTLM Auditing: Configured"
    Write-Host "  [+] Power Settings: High Performance"
    Write-Host "  [+] SAM-R: Configured"
    Write-Host ""
}

Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Run Test-MdiReadiness.ps1 to verify configuration:" -ForegroundColor White
Write-Host "     .\Test-MdiReadiness.ps1 -OpenHtmlReport" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Test DSA permissions:" -ForegroundColor White
Write-Host "     Test-MDIDSA -Identity '$DSAName' -Detailed" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Download and install MDI sensor from Microsoft Defender portal:" -ForegroundColor White
Write-Host "     Settings > Identities > Sensors > Add sensor" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Configure DSA in Microsoft Defender portal:" -ForegroundColor White
Write-Host "     Settings > Identities > Directory Service accounts" -ForegroundColor Gray
Write-Host ""

if ($DSAType -eq 'gMSA') {
    Write-Host "gMSA Account Details:" -ForegroundColor Yellow
    Write-Host "  Account Name: ${DSAName}$" -ForegroundColor White
    Write-Host "  Security Group: $DSAGroupName" -ForegroundColor White
    Write-Host "  DNS Host Name: ${DSAName}.$Domain" -ForegroundColor White
    Write-Host ""
}

Write-Host "SAM-R GPO Configuration (for domain-wide deployment):" -ForegroundColor Yellow
Write-Host "  Policy Path: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options" -ForegroundColor White
Write-Host "  Policy Name: Network access - Restrict clients allowed to make remote calls to SAM" -ForegroundColor White
Write-Host "  Apply To: All workstations and member servers (NOT domain controllers)" -ForegroundColor White
Write-Host ""

Write-Host "VMware/Hyper-V Note:" -ForegroundColor Yellow
Write-Host "  If running on VMware, disable 'Large Send Offload (LSO)' in network adapter properties" -ForegroundColor White
Write-Host "  For Hyper-V, ensure Dynamic Memory is DISABLED and memory is fully allocated" -ForegroundColor White
Write-Host ""
#endregion
