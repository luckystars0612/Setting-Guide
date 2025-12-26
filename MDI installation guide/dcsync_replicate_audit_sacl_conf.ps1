Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName

# Get current SACL
$ACL = Get-Acl "AD:\$DomainDN" -Audit

$EveryoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")

# DS-Replication-Get-Changes
$Guid1 = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$AuditRule1 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $EveryoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $Guid1,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
$ACL.AddAuditRule($AuditRule1)

# DS-Replication-Get-Changes-All
$Guid2 = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$AuditRule2 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $EveryoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $Guid2,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
$ACL.AddAuditRule($AuditRule2)

# DS-Replication-Get-Changes-In-Filtered-Set
$Guid3 = [guid]"89e95b76-444d-4c62-991a-0facbeda640c"
$AuditRule3 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $EveryoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $Guid3,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
$ACL.AddAuditRule($AuditRule3)

# Apply SACL
Set-Acl "AD:\$DomainDN" $ACL

Write-Host "[OK] DCSync replication auditing SACL configured!" -ForegroundColor Green