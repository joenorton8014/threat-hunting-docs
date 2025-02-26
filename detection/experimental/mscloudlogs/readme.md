# Microsoft Expanded Cloud Logs Implementation Scripts

This repository contains PowerShell scripts to help implement the recommendations from CISA's "Microsoft Expanded Cloud Logs Implementation Playbook" (January 2025). These scripts assist with enabling, configuring, and operationalizing Microsoft's expanded cloud logs for enhanced security monitoring and threat detection.

## Background

In response to the 2023 security incident involving Storm-0558 (a PRC-backed hacker group), Microsoft expanded access to enhanced cloud logging capabilities that were previously only available to premium customers. These expanded logs provide critical visibility into activities such as:

- Mail items accessed in Exchange Online
- Search queries in Exchange and SharePoint
- Teams meeting participation and message activities

These logs are essential for detecting and investigating advanced threats, particularly those involving identity compromise and data exfiltration.

## Scripts Overview

### 1. Enable-ExpandedCloudLogs.ps1

This script enables and verifies the expanded cloud logging capabilities in Microsoft 365.

**Features:**
- Checks and enables auditing for mailboxes
- Enables SearchQueryInitiated logging for Exchange and SharePoint
- Verifies that logs are flowing correctly

**Usage:**
```powershell
.\Enable-ExpandedCloudLogs.ps1 -UserPrincipalName user@domain.com
```

### 2. Detect-SuspiciousActivity.ps1

This script implements the scenario-based analysis techniques described in the CISA playbook to detect potential security incidents.

**Features:**
- Detects credential access through accessed mail
- Detects exfiltration through anomalous search activity
- Determines the impact of a compromise through Teams interactions
- Generates an HTML report of findings

**Usage:**
```powershell
# Basic usage (analyzes last 7 days)
.\Detect-SuspiciousActivity.ps1

# Specify a different time period
.\Detect-SuspiciousActivity.ps1 -Days 30

# Include Teams activity analysis
.\Detect-SuspiciousActivity.ps1 -IncludeTeamsActivity

# Specify a custom output path for the report
.\Detect-SuspiciousActivity.ps1 -OutputPath "C:\Reports\SuspiciousActivity.html"
```

### 3. Configure-SIEMIntegration.ps1

This script helps configure the integration of Microsoft expanded cloud logs with SIEM solutions, specifically Microsoft Sentinel and Splunk.

**Features:**
- Configures Microsoft Sentinel data connectors for Office 365
- Creates sample KQL queries for threat detection
- Provides guidance for Splunk integration
- Generates configuration files and helper scripts

**Usage:**
```powershell
# Generate configuration guidance only
.\Configure-SIEMIntegration.ps1 -SIEMType Sentinel -GenerateConfigFilesOnly

# Configure Sentinel integration
.\Configure-SIEMIntegration.ps1 -SIEMType Sentinel -WorkspaceName "YourWorkspace" -ResourceGroupName "YourResourceGroup"

# Generate Splunk integration guidance
.\Configure-SIEMIntegration.ps1 -SIEMType Splunk -GenerateConfigFilesOnly

# Configure Splunk integration
.\Configure-SIEMIntegration.ps1 -SIEMType Splunk -SplunkURL "https://your-splunk-instance:8089"

# Configure both SIEM integrations
.\Configure-SIEMIntegration.ps1 -SIEMType Both -WorkspaceName "YourWorkspace" -ResourceGroupName "YourResourceGroup" -SplunkURL "https://your-splunk-instance:8089"
```

## Prerequisites

- PowerShell 5.1 or higher
- Exchange Online PowerShell module
- Azure PowerShell modules (for Sentinel integration)
- Appropriate permissions:
  - Exchange Administrator or Global Administrator role for enabling logs
  - Audit Reader role in Microsoft Purview for viewing logs
  - Security Admin or Global Administrator role for Sentinel integration
  - Admin access to Splunk instance for Splunk integration

## Installation

1. Clone or download this repository
2. Ensure you have the required PowerShell modules installed:

```powershell
# Install Exchange Online PowerShell module
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

# Install Azure PowerShell modules (for Sentinel integration)
Install-Module -Name Az -Force -AllowClobber
Install-Module -Name Az.SecurityInsights -Force -AllowClobber
```

## Implementation Workflow

For a complete implementation of the CISA playbook recommendations, follow these steps:

1. **Enable expanded cloud logs**:
   ```powershell
   .\Enable-ExpandedCloudLogs.ps1 -UserPrincipalName user@domain.com
   ```

2. **Configure SIEM integration**:
   ```powershell
   # For Sentinel
   .\Configure-SIEMIntegration.ps1 -SIEMType Sentinel -WorkspaceName "YourWorkspace" -ResourceGroupName "YourResourceGroup"
   
   # For Splunk
   .\Configure-SIEMIntegration.ps1 -SIEMType Splunk -SplunkURL "https://your-splunk-instance:8089"
   ```

3. **Run suspicious activity detection**:
   ```powershell
   .\Detect-SuspiciousActivity.ps1 -Days 30 -IncludeTeamsActivity
   ```

4. Review the generated HTML report and investigate any suspicious findings.

## Additional Resources

- [CISA Microsoft Expanded Cloud Logs Implementation Playbook (January 2025)](https://www.cisa.gov/sites/default/files/2025-01/microsoft-expanded-cloud-logs-implementation-playbook-508c.pdf)
- [Microsoft documentation on Purview Audit](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)
- [Microsoft documentation on mailbox auditing](https://learn.microsoft.com/en-us/purview/audit-mailboxes)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
