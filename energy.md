# Energy Sector Threat Hunting Guide

## Threat Actor: XENOTIME
MITRE Group ID: G0874

### Primary TTPs:
1. Initial Access
   - Valid Accounts [T1078]
   - External Remote Services [T1133]
   
2. Execution
   - Command and Scripting Interpreter [T1059]
   - Native API [T1106]

3. Impact
   - Inhibit System Recovery [T1490]
   - Operational Technology Effects [T1495]

### Hunt Methodology:
1. ICS/OT Network Analysis:
   - Monitor for authentication to critical safety systems
   - Baseline normal ICS protocol behavior (Modbus, DNP3, IEC 61850)
   - Look for IT protocols appearing in OT networks (SSH, RDP outside maintenance windows)
   - Analyze timing patterns for safety instrumented system communications
   
2. Safety System Access:
   - Track access to safety instrumented systems (SIS)
   - Monitor for modifications to protection relay settings
   - Look for unusual engineering workstation connections to safety controllers
   - Check for firmware updates to safety systems outside maintenance windows

3. Network Segmentation Monitoring:
   - Track traffic crossing IT/OT boundaries
   - Monitor for unusual protocol usage between zones
   - Look for bypassed security controls between networks
   - Analyze data flows between corporate and control system networks

## Threat Actor: ELECTRUM
MITRE Group ID: G0079

### Primary TTPs:
1. Discovery
   - Network Service Scanning [T1046]
   - Remote System Discovery [T1018]

2. Lateral Movement
   - Remote Services [T1021]
   - Lateral Tool Transfer [T1570]

3. Command and Control
   - Proxy [T1090]
   - Non-Standard Port [T1571]

### Hunt Methodology:
1. Control Network Discovery Detection:
   - Monitor for network scanning in OT environments
   - Look for unusual port/protocol enumeration
   - Track device discovery attempts
   - Monitor for tools like nmap or custom scanners in control networks

2. Remote Access Monitoring:
   - Analyze remote access sessions to control systems
   - Monitor for unusual RDP/SSH sessions to engineering workstations
   - Track authentication to HMIs and control servers
   - Look for unusual access timing to critical infrastructure

3. OT Protocol Analysis:
   - Baseline normal industrial protocol behavior
   - Monitor for unusual commands in industrial protocols
   - Look for protocol anomalies or manipulation
   - Track unauthorized read/write commands to control systems

## Nation State Actor: DRAGONFLY (Energetic Bear)
MITRE Group ID: G0035

### Primary TTPs:
1. Initial Access
   - Supply Chain Compromise [T1195]
   - Spearphishing Attachment [T1566.001]

2. Persistence
   - External Remote Services [T1133]
   - Account Manipulation [T1098]

3. Collection
   - Automated Collection [T1119]
   - Screen Capture [T1113]

### Hunt Methodology:
1. Supply Chain Risk Analysis:
   - Monitor updates to ICS/SCADA software
   - Track digital signatures on vendor packages
   - Look for unexpected changes after vendor updates
   - Analyze behavior of recently updated control systems

2. Remote Access Monitoring:
   - Track vendor VPN access patterns
   - Monitor for unusual access to control systems
   - Look for access outside maintenance windows
   - Analyze authentication attempts from unusual sources

3. Engineering Document Access:
   - Monitor access to network diagrams
   - Track unusual access to control system documentation
   - Look for mass collection of engineering files
   - Analyze access to critical infrastructure design documents

## Nation State Actor: SANDWORM TEAM
MITRE Group ID: G0034

### Primary TTPs:
1. Initial Access
   - Trusted Relationship [T1199]
   - Valid Accounts [T1078]

2. Defense Evasion
   - Masquerading [T1036]
   - Obfuscated Files or Information [T1027]

3. Impact
   - Data Destruction [T1485]
   - Disk Wipe [T1561]

### Hunt Methodology:
1. Privileged Account Monitoring:
   - Track privileged account usage in OT environments
   - Monitor for unusual domain admin account behavior
   - Look for service account misuse
   - Analyze access patterns to critical infrastructure systems

2. Destructive Malware Detection:
   - Monitor for file wiping utilities
   - Look for MBR/VBR modification attempts
   - Track unusual driver installations
   - Analyze systems making multiple file modifications rapidly

3. Critical Infrastructure Monitoring:
   - Create baselines for power management systems
   - Monitor for unusual commands to substations
   - Look for abnormal patterns in SCADA communications
   - Track access to protective relay configurations

## Technical Hunt Implementation

### Data Sources Required:
1. OT/ICS Specific Logs
   - Historian databases
   - RTU/PLC logs
   - HMI access logs
   - Engineering workstation event logs
   - Protective relay access logs

2. Network Traffic
   - Span/TAP from IT/OT boundary points
   - Industrial protocol traffic (Modbus, DNP3, IEC-61850)
   - NetFlow from control networks
   - DNS queries from engineering networks

3. System Logs
   - Windows Event Logs from engineering systems
   - Authentication logs from control servers
   - Remote access logs (VPN, remote desktop)
   - File access logs from engineering workstations

### Hunt Tools and Queries:

1. IEC-61850 Protocol Anomaly Detection:
```python
# Example Python script for detecting anomalous IEC-61850 communications
import pandas as pd
from sklearn.ensemble import IsolationForest

# Load IEC-61850 traffic data
df = pd.read_csv('iec61850_traffic.csv')

# Features for anomaly detection
features = ['function_code', 'data_length', 'intervals', 'source_ip', 'destination_ip']

# One-hot encode categorical features
df_encoded = pd.get_dummies(df, columns=['function_code', 'source_ip', 'destination_ip'])

# Train anomaly detection model
model = IsolationForest(contamination=0.01, random_state=42)
df_encoded['anomaly_score'] = model.fit_predict(df_encoded.drop(['timestamp'], axis=1, errors='ignore'))

# Get anomalies
anomalies = df.loc[df_encoded['anomaly_score'] == -1]
print(f"Detected {len(anomalies)} anomalous IEC-61850 communications")
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
     $_.Message -match "cscript.exe" -or
     $_.Message -match "psexec.exe" -or
     $_.Message -match "rundll32.exe")
}
```

3. Sigma Rule for Detecting Unusual Access to Critical Infrastructure:
```yaml
title: Unusual Access To Critical Energy Infrastructure
status: experimental
description: Detects unusual user accounts accessing critical energy infrastructure systems
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ComputerName|startswith: 
            - 'SCADA-'
            - 'RTU-'
            - 'PLC-'
    filter:
        AccountName|contains:
            - 'SVC_SCADA'
            - 'ENG_OPER'
            - 'MAINT_'
    condition: selection and not filter
    timeframe: 7d
falsepositives:
    - New maintenance personnel
    - Emergency operations
    - Planned maintenance windows
level: high
```

4. Yara Rule for ICS-Targeting Malware:
```
rule ICS_Targeting_Malware_Energy {
    meta:
        description = "Detects malware targeting energy sector ICS environments"
        author = "Energy Sector Security Team"
        severity = "Critical"
    
    strings:
        $ics_protocol1 = "dnp3" ascii nocase wide
        $ics_protocol2 = "modbus" ascii nocase wide
        $ics_protocol3 = "iec61850" ascii nocase wide
        
        $function1 = "ReadCoils" ascii nocase wide
        $function2 = "ReadInputRegisters" ascii nocase wide
        $function3 = "WriteSingleRegister" ascii nocase wide
        
        $energy1 = "substation" ascii nocase wide
        $energy2 = "switchgear" ascii nocase wide
        $energy3 = "generator" ascii nocase wide
        $energy4 = "transmission" ascii nocase wide
    
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($ics_protocol*)) and
        (1 of ($function*)) and
        (1 of ($energy*))
}
```

5. Snort Rule for Detecting Suspicious DNP3 Traffic:
```
# Alert on DNP3 write commands to critical function codes
alert tcp any any -> $SCADA_SUBNET any (msg:"SUSPICIOUS DNP3 WRITE TO CRITICAL FUNCTION"; flow:established; content:"|C0 01|"; depth:2; content:"|03|"; distance:8; within:1; classtype:attempted-admin; sid:1000001; rev:1;)
```

### Hunt Process:

1. Energy Sector-Specific Baselines
   - Document normal operations for power generation/transmission systems
   - Baseline substation communication patterns
   - Map normal access patterns to protective relays and safety systems
   - Document scheduled maintenance windows and remote access patterns

2. Regular Hunt Cadence
   - Daily: Review alerts from critical infrastructure
   - Weekly: Analyze access patterns to engineering workstations
   - Monthly: Review OT network protocol patterns
   - Quarterly: Full review of all safety system access

3. Energy-Specific Response Actions
   - Create ICS incident response procedures
   - Establish isolation methods for compromised systems
   - Develop alternative control procedures during incidents
   - Document recovery processes that maintain grid stability

### Energy Sector-Specific Considerations:

1. Safety Systems Protection
   - Isolate and specially monitor safety systems
   - Create strict baselines for safety system communications
   - Implement enhanced monitoring of safety-critical networks
   - Develop specialized hunting for safety system tampering

2. Grid Stability Impact Analysis
   - Assess potential grid impact before active response
   - Develop hunting techniques with minimal operational disruption
   - Create "safe mode" investigation procedures
   - Document critical systems requiring special handling

3. Infrastructure Protection
   - Monitor access to substation designs and network diagrams
   - Track unusual access to grid topology documentation
   - Alert on mass copying of critical infrastructure information
   - Monitor for exfiltration of grid data

4. Regulatory Compliance
   - Ensure hunting meets NERC CIP requirements
   - Document procedures in compliance with regulatory frameworks
   - Maintain evidence collection compatible with compliance requirements
   - Align hunting program with energy sector compliance frameworks

5. Physical-Cyber Convergence
   - Monitor for correlation between physical access and cyber activity
   - Track badge access to critical facilities alongside system access
   - Look for unusual patterns in combined physical-cyber access
   - Analyze entry system logs in conjunction with network activity

Remember to adjust hunt patterns based on:
- Types of energy generation/transmission
- Critical infrastructure components
- Regulatory requirements
- Operational technology environment
- Safety system architecture
- Grid connectivity and dependencies