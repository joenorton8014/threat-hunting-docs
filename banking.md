# Banking Sector Threat Hunting Guide

## Threat Actor: FIN7
MITRE Group ID: G0046

### Primary TTPs:
1. Initial Access
   - Spearphishing Attachment [T1566.001]
   - Spearphishing Link [T1566.002]
   
2. Execution
   - User Execution [T1204]
   - Command and Scripting Interpreter [T1059]

3. Persistence
   - BITS Jobs [T1197]
   - Registry Run Keys [T1547.001]

### Hunt Methodology:
1. Email Security Analysis:
   - Hunt for emails targeting financial staff with banking-themed lures
   - Look for document attachments with embedded macros
   - Monitor for PDF attachments with embedded links
   - Track unusual sender domains mimicking financial institutions
   
2. Endpoint Process Analysis:
   - Monitor for Office applications spawning cmd.exe, powershell.exe, or wscript.exe
   - Look for unusual BITS job creations
   - Track scheduled tasks created from user documents
   - Analyze PowerShell scripts with obfuscated content

3. Registry Monitoring:
   - Track new registry run keys
   - Monitor for changes to startup folders
   - Look for DLL search order hijacking in banking applications
   - Check for COM hijacking in financial software

## Threat Actor: Carbanak Group
MITRE Group ID: G0008

### Primary TTPs:
1. Credential Access
   - Credentials from Web Browsers [T1555.003]
   - OS Credential Dumping [T1003]

2. Lateral Movement
   - Remote Services [T1021]
   - Internal Spearphishing [T1534]

3. Collection
   - Screen Capture [T1113]
   - Video Capture [T1125]

### Hunt Methodology:
1. Credential Security:
   - Monitor for access to browser credential stores
   - Look for LSASS memory access
   - Track execution of credential dumping tools
   - Analyze authentication patterns for unusual lateral movement

2. Banking System Access:
   - Create baseline of normal banking application usage
   - Monitor for unusual RDP sessions to banking terminals
   - Look for unusual access times to financial applications
   - Track login anomalies to payment processing systems

3. ATM/Payment System Monitoring:
   - Analyze commands sent to ATM networks
   - Monitor for unusual maintenance mode access
   - Track debugging commands to payment card systems
   - Look for unauthorized firmware updates to financial hardware

## Nation State Actor: Lazarus Group (North Korea)
MITRE Group ID: G0032

### Primary TTPs:
1. Initial Access
   - Drive-by Compromise [T1189]
   - Exploit Public-Facing Application [T1190]

2. Defense Evasion
   - Obfuscated Files or Information [T1027]
   - Masquerading [T1036]

3. Impact
   - Data Destruction [T1485]
   - Data Manipulation [T1565]

### Hunt Methodology:
1. Web Application Security:
   - Monitor for exploitation attempts against banking portals
   - Look for unusual web application errors during login processes
   - Track JavaScript injection attempts
   - Analyze web server logs for exploitation signatures

2. Destructive Malware Detection:
   - Monitor for file encryption activities
   - Look for MBR/VBR modification attempts
   - Track suspicious file wiping utilities
   - Analyze system utilities accessing multiple files rapidly

3. SWIFT Network Monitoring:
   - Create baseline of normal SWIFT transaction patterns
   - Monitor for unusual message manipulation
   - Look for unauthorized access to SWIFT terminals
   - Track deviations in normal transaction timing or amounts

## Nation State Actor: APT38 (North Korea)
MITRE Group ID: G0082

### Primary TTPs:
1. Persistence
   - Server Software Component [T1505]
   - Valid Accounts [T1078]

2. Privilege Escalation
   - Exploitation for Privilege Escalation [T1068]
   - Access Token Manipulation [T1134]

3. Exfiltration
   - Exfiltration Over Alternative Protocol [T1048]
   - Scheduled Transfer [T1029]

### Hunt Methodology:
1. Web Server Component Analysis:
   - Monitor for unusual web server module installations
   - Look for unauthorized web shell deployments
   - Track changes to web application components
   - Analyze web server processes making unusual connections

2. Privilege Analysis:
   - Monitor for token manipulation techniques
   - Look for unexpected privilege escalation
   - Track service accounts switching to interactive logons
   - Analyze admin account usage outside normal patterns

3. SWIFT Transaction Monitoring:
   - Create baseline for normal transaction volumes and timing
   - Monitor for unusual transaction patterns
   - Look for manipulation of transaction logs
   - Track accesses to SWIFT-related databases or message stores

## Technical Hunt Implementation

### Data Sources Required:
1. Banking-Specific Logs
   - Core banking application logs
   - SWIFT/payment gateway logs
   - ATM/POS terminal logs
   - Online banking portal logs

2. Network Traffic
   - East-west traffic between banking zones
   - TLS inspection logs from banking applications
   - Session metadata from financial transactions
   - DNS queries from critical financial systems

3. Authentication Logs
   - Multi-factor authentication logs
   - Privileged access management logs
   - Treasury management system logins
   - Wire transfer authorization logs

### Hunt Tools and Queries:

1. SWIFT Transaction Anomaly Detection:
```sql
-- SQL query to detect unusual SWIFT transaction patterns
SELECT 
    transaction_date,
    sender_account,
    recipient_account,
    amount,
    country_code
FROM swift_transactions
WHERE 
    -- Unusual amount threshold
    amount > (SELECT AVG(amount) * 3 FROM swift_transactions 
              WHERE transaction_date > DATEADD(day, -90, GETDATE()))
    -- Unusual time of day
    OR DATEPART(HOUR, transaction_time) NOT BETWEEN 9 AND 18
    -- Unusual destination
    OR country_code IN (
        SELECT country_code
        FROM swift_transactions
        GROUP BY country_code
        HAVING COUNT(*) < 5
        AND MAX(transaction_date) > DATEADD(day, -180, GETDATE())
    )
ORDER BY transaction_date DESC;
```

2. PowerShell Detection for Banking Endpoints:
```powershell
# PowerShell query to detect unusual processes on banking terminals
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=$startTime
} | Where-Object {
    # Filter for banking terminals
    $_.Message -match "BNK-TERM" -and
    # Look for unusual processes on banking terminals
    ($_.Message -match "cmd.exe" -or
     $_.Message -match "powershell.exe" -or
     $_.Message -match "wscript.exe" -or
     $_.Message -match "cscript.exe" -or
     $_.Message -match "regsvr32.exe")
}
```

3. Sigma Rule for Detecting Unusual Access to Banking Applications:
```yaml
title: Unusual Access To Banking Applications
status: experimental
description: Detects unusual user accounts accessing banking applications
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ComputerName|startswith: 'BNKAPP-'
    timeframe: 1d
    condition: selection | count() by AccountName > 10
    filter:
        AccountName|contains:
            - 'SVC_BNK'
            - 'ADM_TREASURY'
            - 'BATCH_'
falsepositives:
    - End of month processing
    - System maintenance windows
level: medium
```

4. Yara Rule for Banking Trojan Detection:
```
rule Banking_Trojan_Indicators {
    meta:
        description = "Detects malware targeting banking applications"
        author = "Banking Security Team"
        severity = "High"
    
    strings:
        $banking1 = "FrmMain" ascii nocase wide
        $banking2 = "TransferFunds" ascii nocase wide
        $banking3 = "SwiftTransfer" ascii nocase wide
        
        $webinject1 = "webinject" ascii nocase wide
        $webinject2 = "grabber" ascii nocase wide
        $webinject3 = "inject.txt" ascii nocase wide
        
        $bank_name1 = "JPMorgan" ascii nocase wide
        $bank_name2 = "Citibank" ascii nocase wide
        $bank_name3 = "HSBC" ascii nocase wide
        $bank_name4 = "Wells Fargo" ascii nocase wide
    
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($banking*)) and
        (1 of ($webinject*)) and
        (1 of ($bank_name*))
}
```

### Hunt Process:

1. Banking-Specific Baselines
   - Document normal transaction volumes by time of day
   - Baseline wire transfer patterns and approval workflows
   - Map normal access patterns to banking applications
   - Document scheduled batch processing windows

2. Regular Hunt Cadence
   - Daily: Review privileged access to banking applications
   - Weekly: Analyze transaction pattern anomalies
   - Monthly: Full review of web application security logs
   - Quarterly: Comprehensive review of user access rights

3. Banking-Specific Response Actions
   - Develop procedures for suspicious transaction containment
   - Create fraud response workflows
   - Establish regulatory reporting procedures
   - Document evidence collection requirements for financial crimes

### Banking-Specific Considerations:

1. Transaction Fraud Analysis
   - Monitor for unusual transaction velocity
   - Track anomalous transaction amounts
   - Look for unusual beneficiary accounts
   - Analyze transaction timing patterns

2. Card Payment Systems
   - Monitor for point-of-sale malware indicators
   - Track card data access patterns
   - Look for unusual card authorization requests
   - Analyze HSM (Hardware Security Module) access logs

3. Regulatory Compliance
   - Ensure hunting meets BSA/AML requirements
   - Document procedures for SAR filing based on hunt findings
   - Maintain evidence in compliance with financial regulations
   - Align hunt capabilities with FFIEC guidance

4. Customer Data Protection
   - Monitor for mass access to customer records
   - Track unusual data export patterns
   - Look for unauthorized access to customer databases
   - Analyze authentication patterns to customer-facing systems

5. Wire Transfer Security
   - Create baseline for normal wire approval workflow
   - Monitor for bypassed approval steps
   - Track unusual wire authorization timing
   - Look for manipulation of beneficiary information

Remember to adjust hunt patterns based on:
- Specific banking services offered
- Payment systems in use
- International transaction patterns
- Regulatory requirements
- Core banking platform architecture
- Third-party payment processor relationships
