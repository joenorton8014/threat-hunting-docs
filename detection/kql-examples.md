# 1. Detect Suspicious Process Creation with Encoded Commands
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

# 2. Identify Potential Lateral Movement via WMI
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

# 3. Detect Potential Credential Dumping Attempts
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

# 4. Identify Unusual Network Connections from System Processes
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

# 5. Detect Potential Persistence via Registry Modifications
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

# 6. Identify Suspicious PowerShell Execution
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

# 7. Detect Potential Malware Injection (Process Access)
DeviceProcessEvents
| where 
    ProcessAccessEvents == true and
    (
        AccessGranted contains "0x1F0FFF" or 
        AccessGranted contains "0x1F1FFF"
    )
| summarize 
    InjectionAttempts = count(),
    DistinctTargets = dcount(TargetProcessName)
by 
    DeviceName, 
    InitiatingProcessFileName, 
    TargetProcessName
| where InjectionAttempts > 2

# 8. Identify Unusual DNS Queries from System Processes
DeviceDnsEvents
| where 
    (ProcessFileName startswith @"C:\Windows\System32\" or 
     ProcessFileName startswith @"C:\Windows\SysWOW64\")
    and DNSQuery !contains "microsoft.com"
    and DNSQuery !contains "windows.com"
| summarize 
    UnusualQueries = count(),
    DistinctDomains = dcount(DNSQuery)
by 
    DeviceName, 
    ProcessFileName, 
    DNSQuery
| where UnusualQueries > 5

# 9. Detect Potential Reconnaissance Activities
DeviceProcessEvents
| where 
    ProcessCommandLine contains "whoami" or
    ProcessCommandLine contains "netstat" or
    ProcessCommandLine contains "ipconfig" or
    ProcessCommandLine contains "netuser"
| summarize 
    ReconCount = count(),
    DistinctHosts = dcount(DeviceName)
by 
    AccountName, 
    ProcessCommandLine
| where ReconCount > 3

# 10. Identify Suspicious Remote Thread Creation
DeviceProcessEvents
| where 
    RemoteThreadCreationEvents == true and
    InitiatingProcessFileName !startswith @"C:\Windows\"
| summarize 
    RemoteThreads = count(),
    DistinctTargets = dcount(TargetProcessName)
by 
    DeviceName, 
    InitiatingProcessFileName, 
    TargetProcessName
| where RemoteThreads > 1

# Detection Engineering Notes:
# - These queries are based on Microsoft Defender for Endpoint / Sentinel
# - Adjust thresholds and conditions to match your specific environment
# - Combine with threat intelligence and additional context
# - Implement robust false positive filtering
# - Correlate with other security data sources
