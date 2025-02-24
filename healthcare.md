# Healthcare Sector Threat Hunting Guide

## Threat Actor: APT41 (WINNTI)
MITRE Group ID: G0096

### Primary TTPs:
1. Initial Access
   - Spearphishing Attachments [T1566.001]
   - Valid Accounts [T1078]
   
2. Execution
   - Command and Scripting Interpreter [T1059]
   - Scheduled Task/Job [T1053]

3. Persistence
   - Create Account [T1136]
   - Registry Run Keys [T1547.001]

### Hunt Methodology:
1. Examine authentication logs for:
   - New service accounts created outside change management windows
   - Accounts with suspicious naming conventions similar to legitimate system accounts
   - Authentication attempts from unexpected geographic locations
   
2. Monitor scheduled tasks:
   - Create baseline of normal scheduled tasks
   - Look for tasks created by service accounts
   - Analyze command lines in scheduled tasks for encoded PowerShell
   - Check for tasks that execute from unusual directories

3. Registry analysis:
   - Monitor for new Run/RunOnce keys
   - Compare against known good baseline
   - Look for encoded commands in registry values
   - Check for persistence mechanisms in HKEY_LOCAL_MACHINE

## Threat Actor: TA505
MITRE Group ID: G0092

### Primary TTPs:
1. Initial Access
   - Phishing [T1566]
   - Drive-by Compromise [T1189]

2. Execution
   - User Execution [T1204]
   - Windows Management Instrumentation [T1047]

3. Command and Control
   - Application Layer Protocol [T1071]
   - Encrypted Channel [T1573]

### Hunt Methodology:
1. Network Analysis:
   - Create SSL/TLS certificate baseline for medical devices
   - Look for unusual SSL/TLS certificates
   - Monitor for unexpected outbound connections from medical devices
   - Analyze DNS queries for entropy (potential DGA)

2. Process Analysis:
   - Monitor for WMI execution patterns
   - Look for processes spawning from unusual parent processes
   - Check for suspicious command-line parameters in WMI calls
   - Track processes making unusual network connections

## Nation State Actor: Lazarus Group (North Korea)
MITRE Group ID: G0032

### Primary TTPs:
1. Defense Evasion
   - Masquerading [T1036]
   - Process Injection [T1055]

2. Lateral Movement
   - Remote Services [T1021]
   - Windows Admin Shares [T1021.002]

3. Collection
   - Data from Local System [T1005]
   - Screen Capture [T1113]

### Hunt Methodology:
1. Process Injection Detection:
   - Monitor for CreateRemoteThread API calls
   - Look for memory allocation patterns indicative of injection
   - Track processes with modified memory sections
   - Analyze parent-child process relationships

2. Lateral Movement Detection:
   - Monitor SMB traffic patterns
   - Look for unusual admin share access
   - Track RDP connection attempts
   - Analyze Windows Event ID 4624 (successful logon) patterns

## Nation State Actor: APT29 (Cozy Bear)
MITRE Group ID: G0016

### Primary TTPs:
1. Initial Access
   - Supply Chain Compromise [T1195]
   - Valid Accounts [T1078]

2. Persistence
   - BITS Jobs [T1197]
   - Modified System Process [T1543]

3. Credential Access
   - OS Credential Dumping [T1003]
   - Credentials from Password Stores [T1555]

### Hunt Methodology:
1. BITS Job Analysis:
   - Monitor for unusual BITS transfers
   - Look for BITS jobs created by unexpected accounts
   - Track BITS jobs with unusual timing patterns
   - Analyze BITS job network destinations

2. Credential Security:
   - Monitor for access to LSASS process
   - Track access to credential vaults
   - Look for mimikatz-like behavior patterns
   - Monitor for suspicious DPAPI operations

## Technical Hunt Implementation

### Data Sources Required:
1. Windows Event Logs
   - Security (ID 4624, 4625, 4688, 4689)
   - System
   - Application
   - PowerShell operational logs

2. Network Traffic
   - NetFlow/IPFIX
   - Full PCAP (if available)
   - SSL/TLS metadata
   - DNS queries and responses

3. EDR/System Logs
   - Process creation/termination
   - File system activity
   - Registry modifications
   - Network connections

### Hunt Tools and Queries:

1. Sysmon Configuration (key events to monitor):
```xml
<EventFiltering>
    <!-- Process Creation -->
    <RuleGroup name="Process Creation" onmatch="include">
        <ProcessCreate onmatch="include"/>
    </RuleGroup>
    <!-- Network Connection -->
    <RuleGroup name="Network Connection" onmatch="include">
        <NetworkConnect onmatch="include"/>
    </RuleGroup>
    <!-- Process Injection -->
    <RuleGroup name="Process Injection" onmatch="include">
        <CreateRemoteThread onmatch="include"/>
    </RuleGroup>
</EventFiltering>
```

2. PowerShell Detection Script:
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {
    $_.Message -match "encoded" -or
    $_.Message -match "downloadstring" -or
    $_.Message -match "bypass"
}
```

3. Sigma Rule for Suspicious Service Creation:
```yaml
title: Suspicious Service Creation
status: experimental
description: Detects service creation from unusual locations
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    condition: selection
    filter:
        ServiceFileName|contains:
            - 'C:\Windows\System32'
            - 'C:\Program Files'
falsepositives:
    - Legitimate service installations
level: medium
```

### Hunt Process:

1. Baseline Establishment
   - Create process baseline for medical devices
   - Document normal network communication patterns
   - Establish standard authentication timing patterns
   - Map legitimate service account behavior

2. Regular Hunt Cadence
   - Daily: Review new service creations
   - Weekly: Analyze authentication patterns
   - Monthly: Full system baseline comparison
   - Quarterly: Comprehensive TTP review

3. Response Actions
   - Document all findings in standard format
   - Create workflow for immediate containment
   - Establish escalation procedures
   - Maintain chain of custody for artifacts

### Healthcare-Specific Considerations:

1. Medical Device Network Segments
   - Monitor for lateral movement attempts
   - Track unusual protocol usage
   - Document baseline communication patterns
   - Alert on deviation from standard patterns

2. PHI Access Patterns
   - Monitor database access timing
   - Track volume of records accessed
   - Alert on unusual access patterns
   - Document legitimate access workflows

3. Regulatory Compliance
   - Maintain HIPAA-compliant logging
   - Document all hunt findings
   - Establish audit trail
   - Ensure proper data handling

Remember to adjust hunt patterns based on:
- Specific medical devices in use
- Network architecture
- Regulatory requirements
- Resource availability
- Threat intelligence updates
