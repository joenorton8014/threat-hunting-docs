<#
.SYNOPSIS
    Detects suspicious activities using Microsoft expanded cloud logs.
    Based on CISA's "Microsoft Expanded Cloud Logs Implementation Playbook"

.DESCRIPTION
    This script implements the scenario-based analysis techniques described in the CISA playbook
    to detect potential security incidents using Microsoft's expanded cloud logs:
    1. Detect credential access through accessed mail
    2. Detect exfiltration through anomalous search activity
    3. Determine the impact of a compromise through Teams interactions

.NOTES
    Requires Exchange Online PowerShell module and appropriate permissions:
    - Exchange Administrator or Global Administrator role
    - Audit Reader role in Microsoft Purview

.EXAMPLE
    .\Detect-SuspiciousActivity.ps1 -Days 7
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$Days = 7,
    
    [Parameter()]
    [string]$OutputPath = ".\SuspiciousActivityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter()]
    [switch]$IncludeTeamsActivity
)

function Test-ExchangeOnlineConnection {
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Connect-ToExchangeOnline {
    try {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
        Connect-ExchangeOnline -ShowBanner:$false
        Write-Host "Successfully connected to Exchange Online." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        exit 1
    }
}

function Get-UnusualMailboxAccess {
    [CmdletBinding()]
    param (
        [int]$Days
    )
    
    Write-Host "Analyzing mailbox access patterns for the past $Days days..." -ForegroundColor Cyan
    
    $startDate = (Get-Date).AddDays(-$Days)
    $endDate = Get-Date
    
    # Get all MailItemsAccessed events
    $mailAccessLogs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MailItemsAccessed -ResultSize 5000
    
    if (-not $mailAccessLogs -or $mailAccessLogs.Count -eq 0) {
        Write-Warning "No MailItemsAccessed logs found for the specified time period."
        return @()
    }
    
    Write-Host "Found $($mailAccessLogs.Count) MailItemsAccessed events. Analyzing patterns..." -ForegroundColor Yellow
    
    # Extract and analyze AppId patterns
    $appIdStats = @{}
    $clientIPStats = @{}
    $userAgentStats = @{}
    $suspiciousEvents = @()
    
    foreach ($log in $mailAccessLogs) {
        $auditData = $log.AuditData | ConvertFrom-Json
        
        # Extract key fields
        $appId = $auditData.AppId
        $clientIP = $auditData.ClientIPAddress
        $clientInfo = $auditData.ClientInfoString
        $userId = $auditData.UserId
        $logonType = $auditData.LogonType
        $timestamp = $log.CreationDate
        
        # Track AppId usage
        if ($appId) {
            if (-not $appIdStats.ContainsKey($appId)) {
                $appIdStats[$appId] = @{
                    Count = 0
                    Users = @{}
                    FirstSeen = $timestamp
                    LastSeen = $timestamp
                }
            }
            
            $appIdStats[$appId].Count++
            $appIdStats[$appId].LastSeen = $timestamp
            
            if (-not $appIdStats[$appId].Users.ContainsKey($userId)) {
                $appIdStats[$appId].Users[$userId] = 0
            }
            $appIdStats[$appId].Users[$userId]++
        }
        
        # Track Client IP usage
        if ($clientIP) {
            if (-not $clientIPStats.ContainsKey($clientIP)) {
                $clientIPStats[$clientIP] = @{
                    Count = 0
                    Users = @{}
                    FirstSeen = $timestamp
                    LastSeen = $timestamp
                }
            }
            
            $clientIPStats[$clientIP].Count++
            $clientIPStats[$clientIP].LastSeen = $timestamp
            
            if (-not $clientIPStats[$clientIP].Users.ContainsKey($userId)) {
                $clientIPStats[$clientIP].Users[$userId] = 0
            }
            $clientIPStats[$clientIP].Users[$userId]++
        }
        
        # Check for suspicious patterns
        $isUnusual = $false
        $reason = ""
        
        # 1. First-time seen AppId
        if ($appId -and (($timestamp - $appIdStats[$appId].FirstSeen).TotalMinutes -lt 60) -and $appIdStats[$appId].Count -lt 5) {
            $isUnusual = $true
            $reason = "Newly observed AppId: $appId"
        }
        
        # 2. AppId accessing multiple mailboxes
        if ($appId -and $appIdStats[$appId].Users.Count -gt 3) {
            $isUnusual = $true
            $reason = "AppId accessing multiple mailboxes ($($appIdStats[$appId].Users.Count)): $appId"
        }
        
        # 3. Unusual client info string
        if ($clientInfo -and $clientInfo -match "(curl|wget|python|powershell|invoke-webrequest)") {
            $isUnusual = $true
            $reason = "Suspicious client user agent: $clientInfo"
        }
        
        # 4. Admin access to mailbox
        if ($logonType -eq "Admin") {
            $isUnusual = $true
            $reason = "Admin access to mailbox"
        }
        
        if ($isUnusual) {
            $suspiciousEvents += [PSCustomObject]@{
                Timestamp = $timestamp
                UserId = $userId
                AppId = $appId
                ClientIP = $clientIP
                ClientInfo = $clientInfo
                LogonType = $logonType
                Reason = $reason
                AuditData = $auditData
            }
        }
    }
    
    # Find IPs accessing multiple mailboxes
    foreach ($ip in $clientIPStats.Keys) {
        if ($clientIPStats[$ip].Users.Count -gt 3) {
            $affectedUsers = $clientIPStats[$ip].Users.Keys -join ", "
            
            # Add to suspicious events if not already included
            $existingEvent = $suspiciousEvents | Where-Object { $_.ClientIP -eq $ip -and $_.Reason -like "*multiple mailboxes*" }
            
            if (-not $existingEvent) {
                $suspiciousEvents += [PSCustomObject]@{
                    Timestamp = $clientIPStats[$ip].LastSeen
                    UserId = "Multiple"
                    AppId = "Various"
                    ClientIP = $ip
                    ClientInfo = "Various"
                    LogonType = "Various"
                    Reason = "IP address accessing multiple mailboxes ($($clientIPStats[$ip].Users.Count))"
                    AuditData = "Affected users: $affectedUsers"
                }
            }
        }
    }
    
    Write-Host "Found $($suspiciousEvents.Count) potentially suspicious mailbox access events." -ForegroundColor Yellow
    return $suspiciousEvents
}

function Get-AnomalousSearchActivity {
    [CmdletBinding()]
    param (
        [int]$Days
    )
    
    Write-Host "Analyzing search activity patterns for the past $Days days..." -ForegroundColor Cyan
    
    $startDate = (Get-Date).AddDays(-$Days)
    $endDate = Get-Date
    
    # Get all SearchQueryInitiated events
    $exchangeSearchLogs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations SearchQueryInitiatedExchange -ResultSize 5000
    $sharepointSearchLogs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations SearchQueryInitiatedSharePoint -ResultSize 5000
    
    $allSearchLogs = @($exchangeSearchLogs) + @($sharepointSearchLogs)
    
    if (-not $allSearchLogs -or $allSearchLogs.Count -eq 0) {
        Write-Warning "No SearchQueryInitiated logs found for the specified time period."
        return @()
    }
    
    Write-Host "Found $($exchangeSearchLogs.Count) Exchange search events and $($sharepointSearchLogs.Count) SharePoint search events." -ForegroundColor Yellow
    
    # Define sensitive search terms
    $sensitiveTerms = @(
        "password", "credential", "secret", "confidential", "private", "vpn", "admin", "key",
        "certificate", "token", "api key", "access", "ssh", "rdp", "ftp", "database",
        "financial", "hr", "salary", "personal", "ssn", "social security", "credit card",
        "bank", "account", "project", "acquisition", "merger", "security", "vulnerability"
    )
    
    # Track search patterns
    $userSearchStats = @{}
    $searchTermStats = @{}
    $suspiciousSearches = @()
    
    foreach ($log in $allSearchLogs) {
        $auditData = $log.AuditData | ConvertFrom-Json
        
        # Extract key fields
        $userId = $auditData.UserId
        $clientIP = $auditData.ClientIP
        $queryText = $auditData.QueryText
        $timestamp = $log.CreationDate
        $operation = $log.Operations
        $workload = if ($operation -eq "SearchQueryInitiatedExchange") { "Exchange" } else { "SharePoint" }
        
        # Skip if no query text (shouldn't happen but just in case)
        if (-not $queryText) { continue }
        
        # Track user search patterns
        if (-not $userSearchStats.ContainsKey($userId)) {
            $userSearchStats[$userId] = @{
                ExchangeSearchCount = 0
                SharePointSearchCount = 0
                SearchTerms = @{}
                TimeWindows = @{}
                LastSeen = $timestamp
            }
        }
        
        if ($workload -eq "Exchange") {
            $userSearchStats[$userId].ExchangeSearchCount++
        }
        else {
            $userSearchStats[$userId].SharePointSearchCount++
        }
        
        $userSearchStats[$userId].LastSeen = $timestamp
        
        if (-not $userSearchStats[$userId].SearchTerms.ContainsKey($queryText)) {
            $userSearchStats[$userId].SearchTerms[$queryText] = 0
        }
        $userSearchStats[$userId].SearchTerms[$queryText]++
        
        # Track time windows (15-minute buckets)
        $timeWindow = Get-Date $timestamp -Format "yyyy-MM-dd HH:mm"
        $timeWindow = $timeWindow.Substring(0, $timeWindow.Length - 1) + "0" # Round to nearest 15 min
        
        if (-not $userSearchStats[$userId].TimeWindows.ContainsKey($timeWindow)) {
            $userSearchStats[$userId].TimeWindows[$timeWindow] = 0
        }
        $userSearchStats[$userId].TimeWindows[$timeWindow]++
        
        # Track search term usage across users
        if (-not $searchTermStats.ContainsKey($queryText)) {
            $searchTermStats[$queryText] = @{
                Count = 0
                Users = @{}
            }
        }
        
        $searchTermStats[$queryText].Count++
        
        if (-not $searchTermStats[$queryText].Users.ContainsKey($userId)) {
            $searchTermStats[$queryText].Users[$userId] = 0
        }
        $searchTermStats[$queryText].Users[$userId]++
        
        # Check for suspicious patterns
        $isUnusual = $false
        $reason = ""
        
        # 1. Check for sensitive terms
        foreach ($term in $sensitiveTerms) {
            if ($queryText -like "*$term*") {
                $isUnusual = $true
                $reason = "Search contains sensitive term: '$term'"
                break
            }
        }
        
        # 2. Check for off-hours searching (assuming 8 AM - 6 PM as normal hours)
        $hour = (Get-Date $timestamp).Hour
        if ($hour -lt 8 -or $hour -gt 18) {
            if ($isUnusual) {
                $reason += " | Off-hours search activity"
            }
            else {
                $isUnusual = $true
                $reason = "Off-hours search activity"
            }
        }
        
        if ($isUnusual) {
            $suspiciousSearches += [PSCustomObject]@{
                Timestamp = $timestamp
                UserId = $userId
                Workload = $workload
                QueryText = $queryText
                ClientIP = $clientIP
                Reason = $reason
                AuditData = $auditData
            }
        }
    }
    
    # Check for users with high search volume in short time periods
    foreach ($user in $userSearchStats.Keys) {
        foreach ($timeWindow in $userSearchStats[$user].TimeWindows.Keys) {
            $count = $userSearchStats[$user].TimeWindows[$timeWindow]
            
            if ($count -gt 10) {
                $suspiciousSearches += [PSCustomObject]@{
                    Timestamp = $userSearchStats[$user].LastSeen
                    UserId = $user
                    Workload = "Multiple"
                    QueryText = "Multiple"
                    ClientIP = "Various"
                    Reason = "High search volume ($count searches) in a short time period"
                    AuditData = "Time window: $timeWindow"
                }
            }
        }
    }
    
    # Check for search terms used by multiple users
    foreach ($term in $searchTermStats.Keys) {
        if ($searchTermStats[$term].Users.Count -gt 3 -and $term.Length -gt 5) {
            $affectedUsers = $searchTermStats[$term].Users.Keys -join ", "
            
            $suspiciousSearches += [PSCustomObject]@{
                Timestamp = Get-Date
                UserId = "Multiple"
                Workload = "Multiple"
                QueryText = $term
                ClientIP = "Various"
                Reason = "Same search term used by multiple users ($($searchTermStats[$term].Users.Count))"
                AuditData = "Affected users: $affectedUsers"
            }
        }
    }
    
    Write-Host "Found $($suspiciousSearches.Count) potentially suspicious search events." -ForegroundColor Yellow
    return $suspiciousSearches
}

function Get-TeamsCompromiseIndicators {
    [CmdletBinding()]
    param (
        [int]$Days
    )
    
    Write-Host "Analyzing Teams activity for compromise indicators for the past $Days days..." -ForegroundColor Cyan
    
    $startDate = (Get-Date).AddDays(-$Days)
    $endDate = Get-Date
    
    # Get Teams-related events
    $teamsEvents = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MeetingParticipantDetail, MessageSent, MessagesListed, MeetingDetail, MessageUpdated, ChatRetrieved, MessageRead -ResultSize 5000
    
    if (-not $teamsEvents -or $teamsEvents.Count -eq 0) {
        Write-Warning "No Teams activity logs found for the specified time period."
        return @()
    }
    
    Write-Host "Found $($teamsEvents.Count) Teams events. Analyzing patterns..." -ForegroundColor Yellow
    
    # Track Teams activity patterns
    $userMeetingStats = @{}
    $userMessageStats = @{}
    $suspiciousTeamsActivity = @()
    
    foreach ($event in $teamsEvents) {
        $auditData = $event.AuditData | ConvertFrom-Json
        
        # Extract key fields
        $userId = $auditData.UserId
        $clientIP = $auditData.ClientIP
        $operation = $event.Operations
        $timestamp = $event.CreationDate
        
        # Track meeting participation
        if ($operation -eq "MeetingParticipantDetail") {
            if (-not $userMeetingStats.ContainsKey($userId)) {
                $userMeetingStats[$userId] = @{
                    MeetingCount = 0
                    MeetingIds = @{}
                    ClientIPs = @{}
                    DeviceTypes = @{}
                }
            }
            
            $userMeetingStats[$userId].MeetingCount++
            
            $meetingId = $auditData.MeetingDetailId
            if ($meetingId) {
                if (-not $userMeetingStats[$userId].MeetingIds.ContainsKey($meetingId)) {
                    $userMeetingStats[$userId].MeetingIds[$meetingId] = 0
                }
                $userMeetingStats[$userId].MeetingIds[$meetingId]++
            }
            
            if ($clientIP) {
                if (-not $userMeetingStats[$userId].ClientIPs.ContainsKey($clientIP)) {
                    $userMeetingStats[$userId].ClientIPs[$clientIP] = 0
                }
                $userMeetingStats[$userId].ClientIPs[$clientIP]++
            }
            
            $deviceInfo = $auditData.DeviceInformation
            if ($deviceInfo) {
                if (-not $userMeetingStats[$userId].DeviceTypes.ContainsKey($deviceInfo)) {
                    $userMeetingStats[$userId].DeviceTypes[$deviceInfo] = 0
                }
                $userMeetingStats[$userId].DeviceTypes[$deviceInfo]++
            }
            
            # Check for suspicious patterns in meeting participation
            $isUnusual = $false
            $reason = ""
            
            # 1. Check for unusual device type
            if ($deviceInfo -and $deviceInfo -match "(Linux|Unknown|curl|wget|python)") {
                $isUnusual = $true
                $reason = "Unusual device type for Teams meeting: $deviceInfo"
            }
            
            # 2. Check for short join/leave times (less than 1 minute)
            if ($auditData.JoinTime -and $auditData.LeaveTime) {
                $joinTime = [DateTime]$auditData.JoinTime
                $leaveTime = [DateTime]$auditData.LeaveTime
                $duration = ($leaveTime - $joinTime).TotalMinutes
                
                if ($duration -lt 1) {
                    if ($isUnusual) {
                        $reason += " | Very short meeting attendance ($($duration.ToString('0.0')) minutes)"
                    }
                    else {
                        $isUnusual = $true
                        $reason = "Very short meeting attendance ($($duration.ToString('0.0')) minutes)"
                    }
                }
            }
            
            if ($isUnusual) {
                $suspiciousTeamsActivity += [PSCustomObject]@{
                    Timestamp = $timestamp
                    UserId = $userId
                    Operation = $operation
                    ClientIP = $clientIP
                    Details = "Meeting ID: $meetingId, Device: $deviceInfo"
                    Reason = $reason
                    AuditData = $auditData
                }
            }
        }
        
        # Track message activity
        if ($operation -in @("MessageSent", "MessagesListed", "MessageUpdated", "MessageRead")) {
            if (-not $userMessageStats.ContainsKey($userId)) {
                $userMessageStats[$userId] = @{
                    MessageCount = 0
                    Operations = @{}
                    ClientIPs = @{}
                    AppIds = @{}
                }
            }
            
            $userMessageStats[$userId].MessageCount++
            
            if (-not $userMessageStats[$userId].Operations.ContainsKey($operation)) {
                $userMessageStats[$userId].Operations[$operation] = 0
            }
            $userMessageStats[$userId].Operations[$operation]++
            
            if ($clientIP) {
                if (-not $userMessageStats[$userId].ClientIPs.ContainsKey($clientIP)) {
                    $userMessageStats[$userId].ClientIPs[$clientIP] = 0
                }
                $userMessageStats[$userId].ClientIPs[$clientIP]++
            }
            
            $appId = $auditData.ClientAppId
            if ($appId) {
                if (-not $userMessageStats[$userId].AppIds.ContainsKey($appId)) {
                    $userMessageStats[$userId].AppIds[$appId] = 0
                }
                $userMessageStats[$userId].AppIds[$appId]++
            }
            
            # Check for suspicious patterns in message activity
            $isUnusual = $false
            $reason = ""
            
            # 1. Check for unusual app IDs
            if ($appId -and $appId -ne "1fec8e78-bce4-4aaf-ab1b-5451cc387264") { # Teams client app ID
                $isUnusual = $true
                $reason = "Unusual app ID for Teams message activity: $appId"
            }
            
            # 2. Check for high volume of message listing (potential data exfiltration)
            if ($operation -eq "MessagesListed" -and $userMessageStats[$userId].Operations[$operation] > 50) {
                if ($isUnusual) {
                    $reason += " | High volume of message listing operations"
                }
                else {
                    $isUnusual = $true
                    $reason = "High volume of message listing operations"
                }
            }
            
            if ($isUnusual) {
                $suspiciousTeamsActivity += [PSCustomObject]@{
                    Timestamp = $timestamp
                    UserId = $userId
                    Operation = $operation
                    ClientIP = $clientIP
                    Details = "App ID: $appId"
                    Reason = $reason
                    AuditData = $auditData
                }
            }
        }
    }
    
    Write-Host "Found $($suspiciousTeamsActivity.Count) potentially suspicious Teams activities." -ForegroundColor Yellow
    return $suspiciousTeamsActivity
}

function Generate-HTMLReport {
    [CmdletBinding()]
    param (
        [array]$MailboxAccessEvents,
        [array]$SearchEvents,
        [array]$TeamsEvents,
        [string]$OutputPath
    )
    
    Write-Host "Generating HTML report at $OutputPath..." -ForegroundColor Cyan
    
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Expanded Cloud Logs - Suspicious Activity Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0078d4; }
        h2 { color: #0078d4; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th { background-color: #0078d4; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary { background-color: #e6f2ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .warning { color: #ff6600; }
        .critical { color: #cc0000; }
        .details { font-family: monospace; white-space: pre-wrap; max-height: 100px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Microsoft Expanded Cloud Logs - Suspicious Activity Report</h1>
    <p>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>This report analyzes Microsoft expanded cloud logs to identify potentially suspicious activities based on the CISA playbook recommendations.</p>
        <ul>
            <li>Suspicious Mailbox Access Events: $($MailboxAccessEvents.Count)</li>
            <li>Suspicious Search Events: $($SearchEvents.Count)</li>
            <li>Suspicious Teams Activities: $($TeamsEvents.Count)</li>
        </ul>
    </div>
"@

    $htmlFooter = @"
</body>
</html>
"@

    $mailboxAccessSection = ""
    if ($MailboxAccessEvents.Count -gt 0) {
        $mailboxAccessSection = @"
    <h2>Suspicious Mailbox Access Events</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>User</th>
            <th>Client IP</th>
            <th>App ID</th>
            <th>Client Info</th>
            <th>Reason</th>
        </tr>
"@

        foreach ($event in $MailboxAccessEvents) {
            $severity = if ($event.Reason -match "(Admin access|multiple mailboxes|Suspicious client)") { "critical" } else { "warning" }
            
            $mailboxAccessSection += @"
        <tr>
            <td>$($event.Timestamp)</td>
            <td>$($event.UserId)</td>
            <td>$($event.ClientIP)</td>
            <td>$($event.AppId)</td>
            <td>$($event.ClientInfo)</td>
            <td class="$severity">$($event.Reason)</td>
        </tr>
"@
        }

        $mailboxAccessSection += "</table>"
    }
    else {
        $mailboxAccessSection = @"
    <h2>Suspicious Mailbox Access Events</h2>
    <p>No suspicious mailbox access events detected.</p>
"@
    }

    $searchSection = ""
    if ($SearchEvents.Count -gt 0) {
        $searchSection = @"
    <h2>Suspicious Search Events</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>User</th>
            <th>Workload</th>
            <th>Query Text</th>
            <th>Client IP</th>
            <th>Reason</th>
        </tr>
"@

        foreach ($event in $SearchEvents) {
            $severity = if ($event.Reason -match "(sensitive term|multiple users)") { "critical" } else { "warning" }
            
            $searchSection += @"
        <tr>
            <td>$($event.Timestamp)</td>
            <td>$($event.UserId)</td>
            <td>$($event.Workload)</td>
            <td>$($event.QueryText)</td>
            <td>$($event.ClientIP)</td>
            <td class="$severity">$($event.Reason)</td>
        </tr>
"@
        }

        $searchSection += "</table>"
    }
    else {
        $searchSection = @"
    <h2>Suspicious Search Events</h2>
    <p>No suspicious search events detected.</p>
"@
    }

    $teamsSection = ""
    if ($TeamsEvents.Count -gt 0) {
        $teamsSection = @"
    <h2>Suspicious Teams Activities</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>User</th>
            <th>Operation</th>
            <th>Client IP</th>
            <th>Details</th>
            <th>Reason</th>
        </tr>
"@

        foreach ($event in $TeamsEvents) {
            $severity = if ($event.Reason -match "(Unusual app ID|Unusual device)") { "critical" } else { "warning" }
            
            $teamsSection += @"
        <tr>
            <td>$($event.Timestamp)</td>
            <td>$($event.UserId)</td>
            <td>$($event.Operation)</td>
            <td>$($event.ClientIP)</td>
            <td>$($event.Details)</td>
            <td class="$severity">$($event.Reason)</td>
        </tr>
"@
        }

        $teamsSection += "</table>"
    }
    else {
        $teamsSection = @"
    <h2>Suspicious Teams Activities</h2>
    <p>No suspicious Teams activities detected.</p>
"@
    }

    $htmlContent = $htmlHeader + $mailboxAccessSection + $searchSection + $teamsSection + $htmlFooter
    $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8
    
    Write-Host "HTML report generated successfully at $OutputPath" -ForegroundColor Green
}

# Main execution
if (-not (Test-ExchangeOnlineConnection)) {
    Connect-ToExchangeOnline
}

try {
    Write-Host "Starting suspicious activity detection using Microsoft expanded cloud logs..." -ForegroundColor Cyan
    Write-Host "Analyzing data for the past $Days days..." -ForegroundColor Cyan
    
    $mailboxAccessEvents = Get-UnusualMailboxAccess -Days $Days
    $searchEvents = Get-AnomalousSearchActivity -Days $Days
    
    $teamsEvents = @()
    if ($IncludeTeamsActivity) {
        $teamsEvents = Get-TeamsCompromiseIndicators -Days $Days
    }
    
    # Generate HTML report
    Generate-HTMLReport -MailboxAccessEvents $mailboxAccessEvents -SearchEvents $searchEvents -TeamsEvents $teamsEvents -OutputPath $OutputPath
    
    Write-Host "`nSuspicious activity detection completed." -ForegroundColor Green
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "- Suspicious Mailbox Access Events: $($mailboxAccessEvents.Count)" -ForegroundColor Yellow
    Write-Host "- Suspicious Search Events: $($searchEvents.Count)" -ForegroundColor Yellow
    
    if ($IncludeTeamsActivity) {
        Write-Host "- Suspicious Teams Activities: $($teamsEvents.Count)" -ForegroundColor Yellow
    }
    
    Write-Host "`nDetailed report saved to: $OutputPath" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
}
