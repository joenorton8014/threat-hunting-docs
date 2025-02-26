<#
.SYNOPSIS
    Configures SIEM integration for Microsoft expanded cloud logs.
    Based on CISA's "Microsoft Expanded Cloud Logs Implementation Playbook"

.DESCRIPTION
    This script helps configure the integration of Microsoft expanded cloud logs with SIEM solutions,
    specifically Microsoft Sentinel and Splunk. It provides guidance and automation for setting up
    the necessary connections and data connectors to ingest the expanded cloud logs into SIEM platforms.

.NOTES
    Requires appropriate permissions:
    - For Sentinel: Security Admin or Global Administrator role
    - For Splunk: Admin access to Splunk instance and appropriate Microsoft 365 permissions

.EXAMPLE
    .\Configure-SIEMIntegration.ps1 -SIEMType Sentinel
    .\Configure-SIEMIntegration.ps1 -SIEMType Splunk
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Sentinel", "Splunk", "Both")]
    [string]$SIEMType,
    
    [Parameter()]
    [string]$WorkspaceName,
    
    [Parameter()]
    [string]$ResourceGroupName,
    
    [Parameter()]
    [string]$SplunkURL,
    
    [Parameter()]
    [switch]$GenerateConfigFilesOnly
)

function Test-AzureConnection {
    try {
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context.Account) {
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

function Connect-ToAzure {
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Cyan
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Successfully connected to Azure." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        return $false
    }
}

function Configure-SentinelIntegration {
    [CmdletBinding()]
    param (
        [string]$WorkspaceName,
        [string]$ResourceGroupName,
        [switch]$GenerateConfigFilesOnly
    )
    
    Write-Host "Configuring Microsoft Sentinel integration for expanded cloud logs..." -ForegroundColor Cyan
    
    if ($GenerateConfigFilesOnly) {
        Write-Host "Generating configuration guidance for Microsoft Sentinel integration..." -ForegroundColor Yellow
        
        $sentinelGuidance = @"
# Microsoft Sentinel Integration Guide for Expanded Cloud Logs

## Prerequisites
- Microsoft Sentinel workspace
- Appropriate permissions (Security Admin or Global Administrator)
- Microsoft 365 E3/E5 or G3/G5 license

## Configuration Steps

### 1. Configure Microsoft 365 Connector in Sentinel

1. In Sentinel, navigate to Data Connectors
2. Search for "Microsoft 365" connector
3. Open the connector page
4. Check the boxes for Exchange, SharePoint, and Teams
5. Click "Apply Changes"

The logs will be populated in the OfficeActivity table within Sentinel.
You can use the following KQL query to check what events are being captured:

```
OfficeActivity
| summarize count() by Operation
```

### 2. Configure Defender XDR Connector in Sentinel (Preview)

1. In Sentinel, navigate to Data Connectors
2. Search for "Defender XDR" connector
3. Open the connector page
4. In the Configuration section, click "Connect Incidents and Alerts"
5. Under "Connect Events", select "Defender for Cloud Apps" and check "CloudAppEvents"
6. Connect Sentinel Workspace in Defender XDR:
   a. In the Microsoft Defender portal (https://security.microsoft.com), go to Settings
   b. Select Microsoft Sentinel
   c. Select your Log Analytics Workspace
   d. Click "Connect Workspace" and confirm

The logs will be populated in the CloudAppEvents table in both Sentinel and Defender XDR.
You can use the following KQL query to check what events are being captured:

```
CloudAppEvents
| summarize count() by ActionType
```

Note: The CloudAppEvents table includes the QueryText field for SearchQueryInitiated logs,
which captures the actual search terms entered by users.

### 3. Sample KQL Queries for Threat Detection

#### Detect Unusual AppId Usage
```
CloudAppEvents
| where ActionType == "MailItemsAccessed"
| extend Accessing_AppId = tostring(RawEventData.AppId)
| summarize count() by bin(Timestamp,1d),Accessing_AppId
| render timechart
```

#### Detect Mail Access from Suspicious IP
```
// Replace x.x.x.x with the suspicious IP address
let bad_sessions = materialize (
  AADSignInEventsBeta
  | where IPAddress == 'x.x.x.x'
  | where isempty(SessionId) == false
  | distinct SessionId
);
CloudAppEvents
| where ActionType == 'MailItemsAccessed'
| where RawEventData.SessionId has_any (bad_sessions)
```

#### Detect Suspicious Search Activity
```
let keywords = dynamic(['secret','password','vpn']); // replace with org-specific keywords
let utc_working_hours = range(2,13); // replace with org-specific working hours
CloudAppEvents
| extend client_ip = tostring(RawEventData.ClientIP)
| extend query_text = tostring(RawEventData.QueryText)
| where ActionType == "SearchQueryInitiatedExchange" or ActionType == "SearchQueryInitiatedSharePoint"
| where not (datetime_part("Hour",Timestamp) in (utc_working_hours))
| where query_text has_any (keywords)
| summarize search_number=count(), make_set(query_text), make_set(client_ip) by AccountDisplayName
```
"@
        
        $sentinelGuidancePath = ".\SentinelIntegrationGuide.md"
        $sentinelGuidance | Out-File -FilePath $sentinelGuidancePath -Encoding utf8
        
        Write-Host "Microsoft Sentinel integration guide has been generated at: $sentinelGuidancePath" -ForegroundColor Green
        return
    }
    
    # Check if required parameters are provided
    if (-not $WorkspaceName -or -not $ResourceGroupName) {
        Write-Error "WorkspaceName and ResourceGroupName are required for Sentinel integration."
        return
    }
    
    # Check Azure connection
    if (-not (Test-AzureConnection)) {
        $connected = Connect-ToAzure
        if (-not $connected) {
            return
        }
    }
    
    # Check if Az.SecurityInsights module is installed
    if (-not (Get-Module -ListAvailable -Name Az.SecurityInsights)) {
        Write-Host "Az.SecurityInsights module is not installed. Installing..." -ForegroundColor Yellow
        Install-Module -Name Az.SecurityInsights -Force -AllowClobber
        Write-Host "Az.SecurityInsights module installed successfully." -ForegroundColor Green
    }
    
    # Import the module
    Import-Module Az.SecurityInsights
    
    # Check if the workspace exists
    try {
        $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction Stop
        Write-Host "Found Log Analytics workspace: $WorkspaceName" -ForegroundColor Green
    }
    catch {
        Write-Error "Log Analytics workspace not found: $_"
        return
    }
    
    # Check if Sentinel is enabled on the workspace
    try {
        $sentinel = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue
        if (-not $sentinel) {
            Write-Host "Enabling Microsoft Sentinel on workspace $WorkspaceName..." -ForegroundColor Yellow
            New-AzSentinelOnboardingState -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop
            Write-Host "Microsoft Sentinel enabled successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Microsoft Sentinel is already enabled on workspace $WorkspaceName." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to enable Microsoft Sentinel: $_"
        return
    }
    
    # Configure Office 365 data connector
    Write-Host "Configuring Office 365 data connector..." -ForegroundColor Yellow
    
    try {
        # Check if Office 365 data connector exists
        $o365Connector = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName | Where-Object { $_.Kind -eq "Office365" }
        
        if ($o365Connector) {
            Write-Host "Office 365 data connector already exists. Updating configuration..." -ForegroundColor Yellow
            
            # Update the connector to ensure all required data types are enabled
            $o365ConnectorParams = @{
                ResourceGroupName = $ResourceGroupName
                WorkspaceName = $WorkspaceName
                Name = $o365Connector.Name
                Kind = "Office365"
                Exchange = $true
                SharePoint = $true
                Teams = $true
            }
            
            Update-AzSentinelDataConnector @o365ConnectorParams
            Write-Host "Office 365 data connector updated successfully." -ForegroundColor Green
        }
        else {
            # Create new Office 365 data connector
            $o365ConnectorParams = @{
                ResourceGroupName = $ResourceGroupName
                WorkspaceName = $WorkspaceName
                Name = "Office365Connector"
                Kind = "Office365"
                Exchange = $true
                SharePoint = $true
                Teams = $true
            }
            
            New-AzSentinelDataConnector @o365ConnectorParams
            Write-Host "Office 365 data connector created successfully." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to configure Office 365 data connector: $_"
    }
    
    # Provide guidance for XDR connector (as it might require manual steps)
    Write-Host "`nGuidance for configuring Defender XDR connector:" -ForegroundColor Yellow
    Write-Host "1. In Sentinel, navigate to Data Connectors and search for 'Defender XDR'" -ForegroundColor Cyan
    Write-Host "2. Open the connector page and click 'Connect Incidents and Alerts'" -ForegroundColor Cyan
    Write-Host "3. Under 'Connect Events', select 'Defender for Cloud Apps' and check 'CloudAppEvents'" -ForegroundColor Cyan
    Write-Host "4. In the Microsoft Defender portal (https://security.microsoft.com):" -ForegroundColor Cyan
    Write-Host "   a. Go to Settings > Microsoft Sentinel" -ForegroundColor Cyan
    Write-Host "   b. Select your Log Analytics Workspace: $WorkspaceName" -ForegroundColor Cyan
    Write-Host "   c. Click 'Connect Workspace' and confirm" -ForegroundColor Cyan
    
    # Create sample KQL queries
    Write-Host "`nCreating sample KQL queries for expanded cloud logs..." -ForegroundColor Yellow
    
    $queries = @(
        @{
            Name = "Detect Unusual AppId Usage"
            Query = @"
CloudAppEvents
| where ActionType == "MailItemsAccessed"
| extend Accessing_AppId = tostring(RawEventData.AppId)
| summarize count() by bin(Timestamp,1d),Accessing_AppId
| render timechart
"@
            Description = "Detects unusual application ID usage patterns in MailItemsAccessed events"
            Tactics = @("CredentialAccess", "Collection")
        },
        @{
            Name = "Detect Suspicious Search Terms"
            Query = @"
let keywords = dynamic(['secret','password','vpn','confidential','credentials']);
CloudAppEvents
| extend client_ip = tostring(RawEventData.ClientIP)
| extend query_text = tostring(RawEventData.QueryText)
| where ActionType == "SearchQueryInitiatedExchange" or ActionType == "SearchQueryInitiatedSharePoint"
| where query_text has_any (keywords)
| summarize search_number=count(), make_set(query_text), make_set(client_ip) by AccountDisplayName
"@
            Description = "Detects searches for sensitive terms in Exchange and SharePoint"
            Tactics = @("Collection", "Exfiltration")
        },
        @{
            Name = "Detect Off-Hours Search Activity"
            Query = @"
let utc_working_hours = range(2,13); // Adjust for your organization's working hours in UTC
CloudAppEvents
| extend client_ip = tostring(RawEventData.ClientIP)
| extend query_text = tostring(RawEventData.QueryText)
| where ActionType == "SearchQueryInitiatedExchange" or ActionType == "SearchQueryInitiatedSharePoint"
| where not (datetime_part("Hour",Timestamp) in (utc_working_hours))
| summarize count() by AccountDisplayName, bin(Timestamp, 1h), tostring(query_text)
| where count_ > 5
"@
            Description = "Detects search activity occurring outside normal business hours"
            Tactics = @("Collection", "Exfiltration")
        },
        @{
            Name = "Detect Teams Meeting Participation from Unusual Devices"
            Query = @"
CloudAppEvents
| where ActionType == "MeetingParticipantDetail"
| extend device_info = tostring(RawEventData.DeviceInformation)
| extend client_ip = tostring(RawEventData.ClientIP)
| where device_info matches regex "Linux|Unknown|curl|wget|python"
| project Timestamp, AccountDisplayName, device_info, client_ip, ActionType
"@
            Description = "Detects Teams meeting participation from unusual or suspicious devices"
            Tactics = @("Collection", "Reconnaissance")
        }
    )
    
    foreach ($query in $queries) {
        try {
            $alertRuleParams = @{
                ResourceGroupName = $ResourceGroupName
                WorkspaceName = $WorkspaceName
                Kind = "Scheduled"
                Name = $query.Name
                Description = $query.Description
                Tactics = $query.Tactics
                Query = $query.Query
                QueryFrequency = New-TimeSpan -Hours 1
                QueryPeriod = New-TimeSpan -Hours 24
                TriggerOperator = "GreaterThan"
                TriggerThreshold = 0
                Severity = "Medium"
                Enabled = $false  # Set to false initially so admins can review and enable as needed
            }
            
            New-AzSentinelAlertRule @alertRuleParams -ErrorAction Stop
            Write-Host "Created alert rule: $($query.Name)" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Host "Alert rule '$($query.Name)' already exists." -ForegroundColor Yellow
            }
            else {
                Write-Error "Failed to create alert rule '$($query.Name)': $_"
            }
        }
    }
    
    Write-Host "`nMicrosoft Sentinel integration for expanded cloud logs has been configured." -ForegroundColor Green
    Write-Host "Please review and enable the created alert rules as needed." -ForegroundColor Yellow
}

function Configure-SplunkIntegration {
    [CmdletBinding()]
    param (
        [string]$SplunkURL,
        [switch]$GenerateConfigFilesOnly
    )
    
    Write-Host "Configuring Splunk integration for expanded cloud logs..." -ForegroundColor Cyan
    
    if ($GenerateConfigFilesOnly) {
        Write-Host "Generating configuration guidance for Splunk integration..." -ForegroundColor Yellow
        
        $splunkGuidance = @"
# Splunk Integration Guide for Microsoft Expanded Cloud Logs

## Prerequisites
- Splunk Enterprise or Splunk Cloud
- Appropriate permissions in Microsoft 365 and Splunk
- Microsoft 365 E3/E5 or G3/G5 license

## Configuration Steps

### 1. Install Required Splunk Add-ons

#### Splunk Add-on for Microsoft Office 365
This add-on allows you to collect service status, service messages, and management activity logs from Office 365.

1. Download the Splunk Add-on for Microsoft Office 365 from Splunkbase: https://splunkbase.splunk.com/app/4055
2. Install the add-on on your Splunk deployment
3. Configure the add-on with appropriate Microsoft 365 credentials

#### Microsoft Graph Security API Add-On for Splunk
This add-on allows you to ingest security alerts using the Microsoft Graph Security API.

1. Download the Microsoft Graph Security API Add-On from Splunkbase: https://splunkbase.splunk.com/app/4564
2. Install the add-on on your Splunk deployment
3. Register a new application in Azure AD for the Splunk add-on
4. Configure the add-on with the registered application credentials

### 2. Configure Office 365 Management Activity API

1. Register an application in Azure AD:
   a. Sign in to the Azure portal
   b. Navigate to Azure Active Directory > App registrations > New registration
   c. Provide a name for the application (e.g., "Splunk Office 365 Integration")
   d. Select "Accounts in this organizational directory only" for Supported account types
   e. Click Register

2. Grant API permissions:
   a. In the registered app, go to API permissions > Add a permission
   b. Select "Office 365 Management APIs"
   c. Select "Application permissions"
   d. Add the following permissions:
      - ActivityFeed.Read
      - ActivityFeed.ReadDlp
      - ServiceHealth.Read
   e. Click "Grant admin consent"

3. Create a client secret:
   a. In the registered app, go to Certificates & secrets > New client secret
   b. Provide a description and select an expiration period
   c. Copy and securely store the generated secret value

4. Configure the Splunk Add-on for Microsoft Office 365:
   a. In Splunk, navigate to the add-on configuration page
   b. Enter the Tenant ID, Client ID, and Client Secret from the registered app
   c. Select the content types to collect (Exchange, SharePoint, Teams)
   d. Save the configuration

### 3. Sample Splunk Searches for Threat Detection

#### Monitor Log Flow
```
index="your_index_for_o365_data" earliest=-30d@d latest=now
    (Operation IN ("MailItemsAccessed", "Send","SearchQueryInitiatedExchange") OR 
     Operation IN ("SearchQueryInitiatedSharePoint") OR 
     Operation IN ("MeetingParticipantDetail", "MessageSent", "MessagesListed", "MeetingDetail", 
                  "MessageUpdated", "ChatRetrieved", "MessageRead"))  
| fields Operation, Workload 
| stats count by Operation, Workload 
| eval operation_status = "identified"  
| append  
    [| makeresults  
    | eval Operation = split("MailItemsAccessed,Send,SearchQueryInitiatedExchange,SearchQueryInitiatedSharePoint,MeetingParticipantDetail,MessageSent,MessagesListed,MeetingDetail,MessageUpdated,ChatRetrieved,MessageRead", ",")  
    | mvexpand Operation  
    | fields - _time]  
| stats values(count) as num_events, values(operation_status) as operation_status, values(Workload) as Workload by Operation  
| fields Operation, Workload, operation_status, num_events  
| sort 0 Workload  
| eval  
    Workload = case(Operation="MailItemsAccessed", "Exchange",  
    Operation="SearchQueryInitiatedExchange", "Exchange",  
    Operation="Send", "Exchange",  
    Operation="MeetingDetail", "MicrosoftTeams",  
    Operation="MeetingParticipantDetail", "MicrosoftTeams",  
    Operation="MessageRead", "MicrosoftTeams",  
    Operation="MessageSent", "MicrosoftTeams",  
    Operation="MessageUpdated", "MicrosoftTeams",  
    Operation="MessagesListed", "MicrosoftTeams",  
    Operation="ChatRetrieved", "MicrosoftTeams",  
    Operation="SearchQueryInitiatedSharePoint", "SharePoint", 1==1, null()),  
    operation_status = case(isnull(operation_status) OR len(operation_status)<=0, "not identified in data", 1==1, operation_status)  
| fillnull value="0" num_events  
| rename num_events as "# of Events", operation_status as "Operation Status" 
```

#### Detect Authentication Failures
```
sourcetype=o365:management:activity eventtype="o365_authentication" 
action=failure NOT LogonError IN ("InvalidReplyTo", "SsoArtifactExpiredDueToConditionalAccess", "BlockedByConditionalAccess") 
NOT user IN (service_test_user@domain.com) 
| eval l_user=lower(user) 
| stats min(_time) AS FT, max(_time) AS LT, values(LogonError) AS errors, values(src) as src, count by l_user  
| where count > 7 
| eval first = strftime(FT, "%Y-%m-%dT%H:%M:%S")   
| eval last = strftime(LT, "%Y-%m-%dT%H:%M:%S")   
| fields l_user errors src first last count 
```

#### Detect Malware in SharePoint/OneDrive
```
sourcetype="o365:management:activity" Workload IN ("OneDrive","SharePoint")   
Operation=FileMalwareDetected  
| table _time, VirusInfo, Workload, ObjectId 
```

#### Detect Large Number of File Modifications
```
sourcetype="o365:management:activity" Workload IN ("SharePoint","OneDrive") 
Operation=FileModified 
| stats sparkline count AS Total_Changes, dc(file_name) AS Distinct_Files_Changed by UserId  
| where Distinct_Files_Changed>=50 
| sort -Distinct_Files_Changed 
```

#### Detect Large Number of File Accesses
```
sourcetype="o365:management:activity" Workload IN ("SharePoint","OneDrive") 
Operation=FileAccessed UserId!=app@sharepoint 
| stats sparkline count AS Total_Accessed, dc(file_name) AS Distinct_Files_Accessed by UserId  
| where Distinct_Files_Accessed >=200 
| sort -Distinct_Files_Accessed 
```
"@
        
        $splunkGuidancePath = ".\SplunkIntegrationGuide.md"
        $splunkGuidance | Out-File -FilePath $splunkGuidancePath -Encoding utf8
        
        Write-Host "Splunk integration guide has been generated at: $splunkGuidancePath" -ForegroundColor Green
        return
    }
    
    # Check if required parameters are provided
    if (-not $SplunkURL) {
        Write-Error "SplunkURL is required for Splunk integration."
        return
    }
    
    # Provide guidance for Splunk integration
    Write-Host "`nGuidance for configuring Splunk integration:" -ForegroundColor Yellow
    Write-Host "1. Install the Splunk Add-on for Microsoft Office 365 from Splunkbase: https://splunkbase.splunk.com/app/4055" -ForegroundColor Cyan
    Write-Host "2. Install the Microsoft Graph Security API Add-On for Splunk: https://splunkbase.splunk.com/app/4564" -ForegroundColor Cyan
    Write-Host "3. Register an application in Azure AD for the Splunk add-on with the following permissions:" -ForegroundColor Cyan
    Write-Host "   - Office 365 Management APIs: ActivityFeed.Read, ActivityFeed.ReadDlp, ServiceHealth.Read" -ForegroundColor Cyan
    Write-Host "4. Configure the Splunk Add-on with your Tenant ID, Client ID, and Client Secret" -ForegroundColor Cyan
    
    # Generate PowerShell script for registering Azure AD application
    $registerAppScript = @"
# PowerShell script to register an Azure AD application for Splunk integration
# Run this script in an elevated PowerShell session with the AzureAD module installed

# Install AzureAD module if not already installed
if (-not (Get-Module -ListAvailable -Name AzureAD)) {
    Install-Module -Name AzureAD -Force -AllowClobber
}

# Connect to Azure AD
Connect-AzureAD

# Register a new application
`$appName = "Splunk Office 365 Integration"
`$app = New-AzureADApplication -DisplayName `$appName -PublicClient `$false

# Create a client secret
`$startDate = Get-Date
`$endDate = `$startDate.AddYears(1)
`$secret = New-AzureADApplicationPasswordCredential -ObjectId `$app.ObjectId -StartDate `$startDate -EndDate `$endDate -CustomKeyIdentifier "SplunkIntegration" -Value (New-Guid).Guid

# Get the service principal
`$sp = New-AzureADServicePrincipal -AppId `$app.AppId

# Define required permissions
`$o365ManagementApi = Get-AzureADServicePrincipal -Filter "AppId eq '00000007-0000-0000-c000-000000000000'"

# ActivityFeed.Read permission
`$activityFeedReadPermission = `$o365ManagementApi.AppRoles | Where-Object { `$_.Value -eq "ActivityFeed.Read" }
`$activityFeedReadResourceAccess = New-Object -TypeName Microsoft.Open.AzureAD.Model.ResourceAccess
`$activityFeedReadResourceAccess.Id = `$activityFeedReadPermission.Id
`$activityFeedReadResourceAccess.Type = "Role"

# ActivityFeed.ReadDlp permission
`$activityFeedReadDlpPermission = `$o365ManagementApi.AppRoles | Where-Object { `$_.Value -eq "ActivityFeed.ReadDlp" }
`$activityFeedReadDlpResourceAccess = New-Object -TypeName Microsoft.Open.AzureAD.Model.ResourceAccess
`$activityFeedReadDlpResourceAccess.Id = `$activityFeedReadDlpPermission.Id
`$activityFeedReadDlpResourceAccess.Type = "Role"

# ServiceHealth.Read permission
`$serviceHealthReadPermission = `$o365ManagementApi.AppRoles | Where-Object { `$_.Value -eq "ServiceHealth.Read" }
`$serviceHealthReadResourceAccess = New-Object -TypeName Microsoft.Open.AzureAD.Model.ResourceAccess
`$serviceHealthReadResourceAccess.Id = `$serviceHealthReadPermission.Id
`$serviceHealthReadResourceAccess.Type = "Role"

# Add all permissions
`$requiredResourceAccess = New-Object -TypeName Microsoft.Open.AzureAD.Model.RequiredResourceAccess
`$requiredResourceAccess.ResourceAppId = `$o365ManagementApi.AppId
`$requiredResourceAccess.ResourceAccess = `$activityFeedReadResourceAccess, `$activityFeedReadDlpResourceAccess, `$serviceHealthReadResourceAccess

# Set permissions on the application
Set-AzureADApplication -ObjectId `$app.ObjectId -RequiredResourceAccess @(`$requiredResourceAccess)

# Output the application details
Write-Host "Application registered successfully!" -ForegroundColor Green
Write-Host "Application Name: `$appName" -ForegroundColor Yellow
Write-Host "Application ID (Client ID): `$(`$app.AppId)" -ForegroundColor Yellow
Write-Host "Directory ID (Tenant ID): `$((Get-AzureADTenantDetail).ObjectId)" -ForegroundColor Yellow
Write-Host "Client Secret: `$(`$secret.Value)" -ForegroundColor Yellow
Write-Host "Note: Save the Client Secret securely as it cannot be retrieved later!" -ForegroundColor Red
"@
    
    $registerAppScriptPath = ".\Register-SplunkAzureADApp.ps1"
    $registerAppScript | Out-File -FilePath $registerAppScriptPath -Encoding utf8
    
    Write-Host "`nA PowerShell script has been generated to help you register an Azure AD application for Splunk integration: $registerAppScriptPath" -ForegroundColor Green
    Write-Host "Run this script to create the application and obtain the required credentials." -ForegroundColor Yellow
    
    # Generate sample Splunk searches
    $splunkSearchesScript = @"
# Sample Splunk Searches for Microsoft Expanded Cloud Logs

# Monitor Log Flow
index="your_index_for_o365_data" earliest=-30d@d latest=now
    (Operation IN ("MailItemsAccessed", "Send","SearchQueryInitiatedExchange") OR 
     Operation IN ("SearchQueryInitiatedSharePoint") OR 
     Operation IN ("MeetingParticipantDetail", "MessageSent", "MessagesListed", "MeetingDetail", 
                  "MessageUpdated", "ChatRetrieved", "MessageRead"))  
| fields Operation, Workload 
| stats count by Operation, Workload 
| eval operation_status = "identified"  
| append  
    [| makeresults  
    | eval Operation = split("MailItemsAccessed,Send,SearchQueryInitiatedExchange,SearchQueryInitiatedSharePoint,MeetingParticipantDetail,MessageSent,MessagesListed,MeetingDetail,MessageUpdated,ChatRetrieved,MessageRead", ",")  
    | mvexpand Operation  
    | fields - _time]  
| stats values(count) as num_events, values(operation_status) as operation_status, values(Workload) as Workload by Operation  
| fields Operation, Workload, operation_status, num_events  
| sort 0 Workload  
| eval  
    Workload = case(Operation="MailItemsAccessed", "Exchange",  
    Operation="SearchQueryInitiatedExchange", "Exchange",  
    Operation="Send", "Exchange",  
    Operation="MeetingDetail", "MicrosoftTeams",  
    Operation="MeetingParticipantDetail", "MicrosoftTeams",  
    Operation="MessageRead", "MicrosoftTeams",  
    Operation="MessageSent", "MicrosoftTeams",  
    Operation="MessageUpdated", "MicrosoftTeams",  
    Operation="MessagesListed", "MicrosoftTeams",  
    Operation="ChatRetrieved", "MicrosoftTeams",  
    Operation="SearchQueryInitiatedSharePoint", "SharePoint", 1==1, null()),  
    operation_status = case(isnull(operation_status) OR len(operation_status)<=0, "not identified in data", 1==1, operation_status)  
| fillnull value="0" num_events  
| rename num_events as "# of Events", operation_status as "Operation Status" 

# Detect Authentication Failures
sourcetype=o365:management:activity eventtype="o365_authentication" 
action=failure NOT LogonError IN ("InvalidReplyTo", "SsoArtifactExpiredDueToConditionalAccess", "BlockedByConditionalAccess") 
NOT user IN (service_test_user@domain.com) 
| eval l_user=lower(user) 
| stats min(_time) AS FT, max(_time) AS LT, values(LogonError) AS errors,
