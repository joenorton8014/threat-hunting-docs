# 1. Detect Suspicious Process Creation with Encoded Commands
index=sysmon EventCode=1 CommandLine="*-enc*" OR CommandLine="*frombase64string*"
| stats count by host, User, Image, CommandLine
| where count > 5

# 2. Identify Potential Lateral Movement via WMI
index=sysmon EventCode=1 Image="*wmiprvse.exe*" ParentImage!="%SystemRoot%\\System32\\wbem\\wmiprvse.exe"
| stats count by host, User, Image, ParentImage
| where count > 2

# 3. Detect Potential Credential Dumping Attempts
index=sysmon (EventCode=1 Image IN ("*mimikatz*", "*procdump*", "*pwdump*")) OR 
(EventCode=10 TargetImage IN ("*lsass.exe*"))
| stats count by host, User, Image, TargetImage
| where count > 0

# 4. Identify Unusual Network Connections from System Processes
index=sysmon EventCode=3 Image IN ("%SystemRoot%\\System32\\*", "%SystemRoot%\\SysWOW64\\*")
NOT DestinationHostname IN ("*.microsoft.com", "*.windows.com", "*.windowsupdate.com")
| stats count by host, User, Image, DestinationIp, DestinationHostname
| where count > 5

# 5. Detect Potential Persistence via Registry Modifications
index=sysmon EventCode=13 
(ObjectValueName="*RunOnce*" OR ObjectValueName="*Run*" OR ObjectValueName="*Startup*")
ObjectValueName!="*UpdateCheck*"
| stats count by host, User, Image, ObjectValueName
| where count > 2

# 6. Identify Suspicious PowerShell Execution
index=sysmon EventCode=1 Image="*powershell.exe*" 
(CommandLine="*-w hidden*" OR CommandLine="*bypass*" OR CommandLine="*noprofile*")
| stats count by host, User, CommandLine
| where count > 3

# 7. Detect Potential Malware Injection (Process Hollowing)
index=sysmon EventCode=10 
(GrantedAccess="0x1F0FFF" OR GrantedAccess="0x1F1FFF")
| stats count by host, SourceImage, TargetImage
| where count > 2

# 8. Identify Unusual DNS Queries from System Processes
index=sysmon EventCode=22 
Image IN ("%SystemRoot%\\System32\\*", "%SystemRoot%\\SysWOW64\\*")
QueryName!="*.microsoft.com" QueryName!="*.windows.com"
| stats count by host, Image, QueryName
| where count > 5

# 9. Detect Potential Reconnaissance Activities
index=sysmon EventCode=1 
(CommandLine="*whoami*" OR CommandLine="*netstat*" OR CommandLine="*ipconfig*" OR CommandLine="*netuser*")
| stats count by host, User, CommandLine
| where count > 3

# 10. Identify Suspicious Remote Thread Creation
index=sysmon EventCode=8 
StartModule!="*%SystemRoot%*" AND StartModule!="*\\Windows\\*"
| stats count by host, SourceImage, TargetImage, StartModule
| where count > 1

# Notes for Detection Engineers:
# - Adjust thresholds based on your environment
# - Whitelist known legitimate processes
# - Combine these queries with threat intelligence
# - Tune detection rules to reduce false positives
# - Implement correlation with other log sources
