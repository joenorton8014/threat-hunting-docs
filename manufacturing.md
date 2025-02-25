# Manufacturing Sector Threat Hunting Guide

## Threat Actor: XENOTIME
MITRE Group ID: G0874

### Primary TTPs:
1. Initial Access
   - Spearphishing Attachments [T1566.001]
   - External Remote Services [T1133]
   
2. Execution
   - Command and Scripting Interpreter [T1059]
   - System Services [T1569]

3. Persistence
   - External Remote Services [T1133]
   - Valid Accounts [T1078]

### Hunt Methodology:
1. OT/ICS Network Analysis:
   - Monitor for unauthorized connections to ICS/SCADA systems
   - Baseline normal OT protocol behavior (Modbus, Profinet, EtherNet/IP)
   - Look for IT protocols appearing in OT networks (HTTP, SSH outside maintenance windows)
   - Analyze timing patterns for industrial process communications
   
2. Service Account Monitoring:
   - Track service account usage patterns
   - Monitor for remote access using service accounts
   - Look for service accounts accessing unusual systems
   - Check for modifications to service account permissions

3. Credential Analysis:
   - Monitor for new accounts with elevated privileges
   - Track access to OT jump servers
   - Review VPN connections to production networks
   - Analyze failed authentication attempts to HMIs and engineering workstations

## Threat Actor: TEMP.Veles
MITRE Group ID: G0088

### Primary TTPs:
1. Discovery
   - Network Service Scanning [T1046]
   - Remote System Discovery [T1018]

2. Lateral Movement
   - Lateral Tool Transfer [T1570]
   - Remote Services [T1021]

3. Impact
   - Inhibit System Recovery [T1490]
   - System Shutdown/Reboot [T1529]

### Hunt Methodology:
1. Network Discovery Detection:
   - Monitor for network scanning activities from engineering workstations
   - Look for unusual port/service enumeration
   - Track unexpected protocol usage across OT/IT boundaries
   - Monitor for tools like nmap or custom scanners

2. Lateral Movement Tracking:
   - Analyze SMB file transfers between zones
   - Monitor for unusual RDP/SSH sessions
   - Track file transfers to critical OT systems
   - Look for unauthorized tools moving across network segments

3. System Impact Monitoring:
   - Track modifications to backup systems
   - Monitor for unusual system reboots
   - Look for unauthorized changes to PLC programming
   - Analyze attempts to modify safety systems

## Nation State Actor: DRAGONFLY (Energetic Bear)
MITRE Group ID: G0035

### Primary TTPs:
1. Initial Access
   - Supply Chain Compromise [T1195]
   - Trusted Relationship [T1199]

2. Defense Evasion
   - Masquerading [T1036]
   - Signed Binary Proxy Execution [T1218]

3. Collection
   - Automated Collection [T1119]
   - Data from Information Repositories [T1213]

### Hunt Methodology:
1. Supply Chain Risk Analysis:
   - Monitor updates to ICS/OT software
   - Track digital signatures on vendor packages
   - Look for unexpected vendor connections
   - Analyze behavior of recently updated systems

2. Binary Analysis:
   - Monitor for signed binaries making unusual connections
   - Look for DLL side-loading attempts
   - Track processes with mismatched file/signature information
   - Analyze execution of trusted utilities that spawn unexpected processes

3. Data Collection Detection:
   - Monitor for mass file access on engineering repositories
   - Track unusual data transfer volumes
   - Look for unexpected access to product designs/specifications
   - Analyze scheduled tasks that access sensitive data repositories

## Nation State Actor: APT10 (Stone Panda)
MITRE Group ID: G0045

### Primary TTPs:
1. Initial Access
   - Spearphishing with Link [T1566.002]
   - Valid Accounts [T1078]

2. Credential Access
   - Input Capture [T1056]
   - Unsecured Credentials [T1552]

3. Exfiltration
   - Exfiltration Over C2 Channel [T1041]
   - Scheduled Transfer [T1029]

### Hunt Methodology:
1. Phishing Detection:
   - Monitor for unusual email links related to manufacturing processes
   - Look for emails targeting specific engineering or production staff
   - Track emails with industrial terminology but from outside normal supply chain
   - Analyze email links for redirects or suspicious domains

2. Credential Protection:
   - Monitor for access to credential stores
   - Track keylogging behavior
   - Look for password harvesting tools
   - Analyze access to sensitive configuration files containing credentials

3. Data Exfiltration Detection:
   - Establish baseline for normal data movement
   - Look for data leaving the network at regular intervals
   - Monitor for connections to unusual cloud storage services
   - Track volume and timing of outbound connections from OT/production networks

## Technical Hunt Implementation

### Data Sources Required:
1. OT/ICS Specific Logs
   - Historian databases
   - PLC/RTU logs (if available)
   - HMI access logs
   - Engineering workstation event logs

2. Network Traffic
   - Span/TAP from OT/IT boundary points
   - NetFlow from critical manufacturing systems
   - Deep packet inspection for industrial protocols
   - DNS queries from engineering networks

3. System Logs
   - Windows Event Logs from engineering systems
   - Authentication logs from jump servers
   - Process creation logs from operator workstations
   - File access logs from product design systems

### Hunt Tools and Queries:

1. OT Network Baseline Monitoring:
```python
# Example Python script for detecting abnormal OT protocol behavior
import pandas as pd
from sklearn.ensemble import IsolationForest

# Load netflow data
df = pd.read_csv('ot_netflow.csv')

# Features for anomaly detection
features = ['bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'duration']

# Train anomaly detection model
model = IsolationForest(contamination=0.01, random_state=42)
df['anomaly_score'] = model.fit_predict(df[features])

# Get anomalies
anomalies = df[df['anomaly_score'] == -1]
print(f"Detected {len(anomalies)} anomalous network flows")
```

2. Windows Event Query for Engineering Workstations:
```powershell
# PowerShell query to detect unusual process creation on engineering workstations
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=$startTime
} | Where-Object {
    # Filter for engineering workstations
    $_.Message -match "ENG-" -and
    # Look for unusual processes
    ($_.Message -match "cmd.exe" -or
     $_.Message -match "powershell.exe" -or
     $_.Message -match "wscript.exe" -or
     $_.Message -match "cscript.exe")
}
```

3. Sigma Rule for Detecting Unusual Access to PLCs:
```yaml
title: Unusual Access To PLC Systems
status: experimental
description: Detects unusual user accounts accessing PLCs or engineering systems
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ComputerName|startswith: 'PLC-'
    condition: selection
    filter:
        AccountName|contains:
            - 'SVC_PLC'
            - 'ENG_OPER'
            - 'MAINT_'
falsepositives:
    - New maintenance personnel
    - Temporary contractor access
level: high
```

4. Yara Rule for Detecting ICS-Targeting Malware:
```
rule ICS_Targeting_Malware {
    meta:
        description = "Detects malware targeting ICS environments"
        author = "Manufacturing Security Team"
        severity = "High"
    
    strings:
        $ics_protocol1 = "s7comm" ascii nocase wide
        $ics_protocol2 = "modbus" ascii nocase wide
        $ics_protocol3 = "profinet" ascii nocase wide
        
        $function1 = "ReadCoils" ascii nocase wide
        $function2 = "ReadInputRegisters" ascii nocase wide
        $function3 = "WriteSingleRegister" ascii nocase wide
        
        $vendor1 = "Siemens" ascii nocase wide
        $vendor2 = "Rockwell" ascii nocase wide
        $vendor3 = "Schneider" ascii nocase wide
    
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($ics_protocol*)) and
        (1 of ($function*)) and
        (1 of ($vendor*))
}
```

### Hunt Process:

1. Establish Manufacturing-Specific Baselines
   - Document normal production cycles and their network patterns
   - Baseline PLC programming access (who, when, how often)
   - Map normal data flows between enterprise and OT networks
   - Document authorized maintenance windows and remote access patterns

2. Regular Hunt Cadence
   - Daily: Review alerts from critical production systems
   - Weekly: Analyze access patterns to engineering workstations
   - Monthly: Review ICS network communication patterns
   - Quarterly: Full review of all remote access to OT systems

3. Manufacturing-Specific Response Actions
   - Create ICS-specific incident response procedures
   - Establish safe system isolation methods that won't impact production
   - Develop alternate production methods for critical systems
   - Document recovery processes that maintain product quality

### Manufacturing-Specific Considerations:

1. Production Impact Analysis
   - Assess potential production impact before active response
   - Develop hunting techniques with minimal OT disruption
   - Create "safe mode" investigation procedures
   - Document critical production systems requiring special handling

2. Intellectual Property Protection
   - Monitor access to product designs and specifications
   - Track unusual access to manufacturing process documentation
   - Alert on mass copying of proprietary production techniques
   - Monitor for exfiltration of quality control data

3. Supply Chain Security
   - Track vendor remote access to production systems
   - Monitor updates to ICS/SCADA systems
   - Validate integrity of industrial software updates
   - Verify digital signatures on automation software

4. Safety Systems Protection
   - Isolate and specially monitor safety systems
   - Create strict baselines for safety system communications
   - Implement enhanced monitoring of safety-critical networks
   - Develop specialized hunting for safety system tampering

Remember to adjust hunt patterns based on:
- Types of manufacturing processes
- Critical production systems
- Intellectual property value
- Regulatory requirements
- Operational technology environment
- Supply chain relationships
