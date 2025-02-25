# Sysmon Threat Detection Queries

## Overview
This document provides comprehensive detection queries for identifying malicious activities using Sysmon logs. Each query is demonstrated in both Splunk SPL and Kusto Query Language (KQL) to showcase cross-platform detection capabilities.

## 1. Encoded Command Execution Detection
### Query Purpose
Identify potential malicious activities using encoded or obfuscated command executions.

### Detection Techniques
- Look for Base64 encoded commands
- Detect suspicious PowerShell encoding patterns
- Flag unusual command obfuscation

### Splunk Query
```splunk
index=sysmon EventCode=1 CommandLine="*-enc*" OR CommandLine="*frombase64string*"
| stats count by host, User, Image, CommandLine
| where count > 5
```

### KQL Query
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "frombase64string"
| summarize 
    EventCount = count(),
    DistinctUsers = dcount(AccountName),
    RecentHosts = make_set(DeviceName, 3)
by 
    AccountName, 
    ProcessCommandLine, 
    InitiatingProcessFileName
| where EventCount > 5
```

## 2. Lateral Movement via WMI Detection
### Query Purpose
Identify potential lateral movement attempts using Windows Management Instrumentation (WMI)

### Detection Techniques
- Track unusual WMI process creations
- Identify non-standard WMI service invocations
- Monitor for suspicious WMI activity

### Splunk Query
```splunk
index=sysmon EventCode=1 Image="*wmiprvse.exe*" ParentImage!="%SystemRoot%\\System32\\wbem\\wmiprvse.exe"
| stats count by host, User, Image, ParentImage
| where count > 2
```

### KQL Query
```kql
DeviceProcessEvents
| where ProcessFileName =~ "wmiprvse.exe" 
  and InitiatingProcessFileName !~ "wmiprvse.exe"
| summarize 
    LateralMovementCount = count(),
    DistinctHosts = dcount(DeviceName)
by 
    AccountName, 
    InitiatingProcessFileName, 
    ProcessCommandLine
| where LateralMovementCount > 2
```

## 3. Credential Dumping Attempts
### Query Purpose
Detect potential credential harvesting and memory dumping activities

### Detection Strategies
- Monitor for known credential dumping tools
- Track access to sensitive system processes
- Identify suspicious interactions with LSASS

### Splunk Query
```splunk
index=sysmon (EventCode=1 Image IN ("*mimikatz*", "*procdump*", "*pwdump*")) OR 
(EventCode=10 TargetImage IN ("*lsass.exe*"))
| stats count by host, User, Image, TargetImage
| where count > 0
```

### KQL Query
```kql
DeviceProcessEvents
| where 
    (ProcessFileName in~ ("mimikatz.exe", "procdump.exe", "pwdump.exe")) or
    (TargetProcessName =~ "lsass.exe" and InitiatingProcessFileName !in~ ("procmon.exe", "procexp.exe"))
| summarize 
    DumpAttempts = count(),
    DistinctHosts = dcount(DeviceName)
by 
    AccountName, 
    InitiatingProcessFileName, 
    TargetProcessName
```

## 4. Unusual Network Connections
### Query Purpose
Identify suspicious network connections from system processes

### Detection Approach
- Filter network connections from system directories
- Exclude known legitimate destinations
- Highlight unexpected external communications

### Splunk Query
```splunk
index=sysmon EventCode=3 Image IN ("%SystemRoot%\\System32\\*", "%SystemRoot%\\SysWOW64\\*")
NOT DestinationHostname IN ("*.microsoft.com", "*.windows.com", "*.windowsupdate.com")
| stats count by host, User, Image, DestinationIp, DestinationHostname
| where count > 5
```

### KQL Query
```kql
DeviceNetworkEvents
| where 
    InitiatingProcessFileName startswith @"C:\Windows\System32\" or 
    InitiatingProcessFileName startswith @"C:\Windows\SysWOW64\"
| where 
    RemoteUrl !contains "microsoft.com" and 
    RemoteUrl !contains "windows.com"
| summarize 
    ConnectionCount = count(),
    DistinctDestinations = dcount(RemoteIP)
by 
    DeviceName, 
    AccountName, 
    InitiatingProcessFileName, 
    RemoteIP, 
    RemoteUrl
| where ConnectionCount > 5
```

## 5. Persistence Mechanism Detection
### Query Purpose
Identify potential persistence mechanisms through registry modifications

### Detection Techniques
- Monitor registry run keys
- Track unauthorized startup entries
- Detect suspicious registry changes

### Splunk Query
```splunk
index=sysmon EventCode=13 
(ObjectValueName="*RunOnce*" OR ObjectValueName="*Run*" OR ObjectValueName="*Startup*")
ObjectValueName!="*UpdateCheck*"
| stats count by host, User, Image, ObjectValueName
| where count > 2
```

### KQL Query
```kql
DeviceRegistryEvents
| where 
    RegistryKey contains @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" or
    RegistryKey contains @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
| where 
    RegistryValueName !contains "UpdateCheck"
| summarize 
    ModificationCount = count(),
    DistinctHosts = dcount(DeviceName)
by 
    AccountName, 
    RegistryKey, 
    RegistryValueName, 
    InitiatingProcessFileName
| where ModificationCount > 2
```

## 6. Suspicious PowerShell Execution
### Query Purpose
Identify potentially malicious PowerShell usage patterns

### Splunk Query
```splunk
index=sysmon EventCode=1 Image="*powershell.exe*" 
(CommandLine="*-w hidden*" OR CommandLine="*bypass*" OR CommandLine="*noprofile*")
| stats count by host, User, CommandLine
| where count > 3
```

### KQL Query
```kql
DeviceProcessEvents
| where 
    ProcessFileName =~ "powershell.exe"
    and (
        ProcessCommandLine contains "-w hidden" or 
        ProcessCommandLine contains "bypass" or 
        ProcessCommandLine contains "noprofile"
    )
| summarize 
    SuspiciousExecutions = count(),
    DistinctUsers = dcount(AccountName)
by 
    AccountName, 
    ProcessCommandLine
| where SuspiciousExecutions > 3
```

## Detection Engineering Best Practices

### Continuous Improvement
1. Regularly update detection rules
2. Implement robust false positive filtering
3. Correlate across multiple log sources
4. Maintain a threat intelligence database

### Key Considerations
- Context is critical
- No single query is 100% accurate
- Combine multiple detection techniques
- Understand your specific environment

## Threat Hunting Maturity Model

### Level 1: Reactive Detection
- Basic log collection
- Simple correlation rules
- Minimal threat intelligence

### Level 2: Proactive Monitoring
- Advanced query development
- Threat hunting capabilities
- Continuous rule refinement

### Level 3: Predictive Defense
- Machine learning integration
- Behavioral analytics
- Automated threat response

## Conclusion
Effective threat detection requires a multi-layered approach, continuous learning, and adaptive strategies. These queries provide a cross-platform foundation for robust security monitoring across different SIEM and log analysis platforms.

---

**Note**: Always test and validate queries in your specific environment. Threat landscapes evolve continuously, and detection techniques must adapt accordingly.
