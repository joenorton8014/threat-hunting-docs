<#
.SYNOPSIS
    Enables Microsoft expanded cloud logs for enhanced security monitoring.
    Based on CISA's "Microsoft Expanded Cloud Logs Implementation Playbook"

.DESCRIPTION
    This script enables the expanded cloud logging capabilities in Microsoft 365,
    including MailItemsAccessed, SearchQueryInitiated for Exchange and SharePoint,
    and verifies that logging is properly configured.

.NOTES
    Requires Exchange Online PowerShell module and appropriate permissions:
    - Exchange Administrator or Global Administrator role

.EXAMPLE
    .\Enable-ExpandedCloudLogs.ps1 -UserPrincipalName user@domain.com
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName
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

function Enable-ExpandedLogging {
    param (
        [string]$UserPrincipalName
    )

    Write-Host "`nChecking audit configuration for user: $UserPrincipalName" -ForegroundColor Cyan
    
    # Get current mailbox audit settings
    $mailbox = Get-Mailbox $UserPrincipalName -ErrorAction Stop | Select-Object *audit*
    
    Write-Host "Current audit configuration:" -ForegroundColor Yellow
    Write-Host "AuditEnabled: $($mailbox.AuditEnabled)"
    Write-Host "AuditLogAgeLimit: $($mailbox.AuditLogAgeLimit)"
    Write-Host "DefaultAuditSet: $($mailbox.DefaultAuditSet -join ', ')"
    
    # Check if auditing is enabled
    if (-not $mailbox.AuditEnabled) {
        Write-Host "`nEnabling auditing for mailbox..." -ForegroundColor Yellow
        Set-Mailbox $UserPrincipalName -AuditEnabled $true
        Write-Host "Auditing enabled successfully." -ForegroundColor Green
    }
    
    # Get current audit actions
    Write-Host "`nChecking audit actions for each sign-in type..." -ForegroundColor Cyan
    
    $auditAdmin = Get-Mailbox $UserPrincipalName | Select-Object -ExpandProperty AuditAdmin
    $auditDelegate = Get-Mailbox $UserPrincipalName | Select-Object -ExpandProperty AuditDelegate
    $auditOwner = Get-Mailbox $UserPrincipalName | Select-Object -ExpandProperty AuditOwner
    
    Write-Host "AuditAdmin actions: $($auditAdmin -join ', ')" -ForegroundColor Yellow
    Write-Host "AuditDelegate actions: $($auditDelegate -join ', ')" -ForegroundColor Yellow
    Write-Host "AuditOwner actions: $($auditOwner -join ', ')" -ForegroundColor Yellow
    
    # Check if SearchQueryInitiated is enabled for AuditOwner
    if ($auditOwner -notcontains "SearchQueryInitiated") {
        Write-Host "`nEnabling SearchQueryInitiated for AuditOwner..." -ForegroundColor Yellow
        Set-Mailbox $UserPrincipalName -AuditOwner @{Add="SearchQueryInitiated"}
        Write-Host "SearchQueryInitiated enabled for AuditOwner." -ForegroundColor Green
        
        # Note about DefaultAuditSet
        Write-Host "Note: Enabling SearchQueryInitiated removes the sign-in type from DefaultAuditSet." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nSearchQueryInitiated is already enabled for AuditOwner." -ForegroundColor Green
    }
    
    # Verify the changes
    Write-Host "`nVerifying configuration changes..." -ForegroundColor Cyan
    $updatedMailbox = Get-Mailbox $UserPrincipalName | Select-Object *audit*
    $updatedAuditOwner = Get-Mailbox $UserPrincipalName | Select-Object -ExpandProperty AuditOwner
    
    Write-Host "Updated DefaultAuditSet: $($updatedMailbox.DefaultAuditSet -join ', ')" -ForegroundColor Yellow
    Write-Host "Updated AuditOwner actions: $($updatedAuditOwner -join ', ')" -ForegroundColor Yellow
    
    if ($updatedAuditOwner -contains "SearchQueryInitiated") {
        Write-Host "`nConfiguration completed successfully!" -ForegroundColor Green
    }
    else {
        Write-Host "`nConfiguration may not have applied correctly. Please check manually." -ForegroundColor Red
    }
}

function Verify-LogsAreFlowing {
    param (
        [string]$UserPrincipalName
    )
    
    Write-Host "`nVerifying logs are flowing for user: $UserPrincipalName" -ForegroundColor Cyan
    Write-Host "Checking for recent MailItemsAccessed logs..." -ForegroundColor Yellow
    
    $startDate = (Get-Date).AddDays(-7)
    $endDate = Get-Date
    
    try {
        $logs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MailItemsAccessed -UserIds $UserPrincipalName -ResultSize 10
        
        if ($logs -and $logs.Count -gt 0) {
            Write-Host "Found $($logs.Count) MailItemsAccessed logs for the user." -ForegroundColor Green
            Write-Host "Sample log entry:" -ForegroundColor Yellow
            $logs[0] | Select-Object CreationDate, UserIds, Operations | Format-List
        }
        else {
            Write-Host "No MailItemsAccessed logs found for the user in the past 7 days." -ForegroundColor Yellow
            Write-Host "This could be normal if the user hasn't accessed their mailbox recently." -ForegroundColor Yellow
        }
        
        Write-Host "`nChecking for SearchQueryInitiated logs..." -ForegroundColor Yellow
        $searchLogs = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations SearchQueryInitiatedExchange -UserIds $UserPrincipalName -ResultSize 10
        
        if ($searchLogs -and $searchLogs.Count -gt 0) {
            Write-Host "Found $($searchLogs.Count) SearchQueryInitiatedExchange logs for the user." -ForegroundColor Green
        }
        else {
            Write-Host "No SearchQueryInitiatedExchange logs found for the user in the past 7 days." -ForegroundColor Yellow
            Write-Host "This could be normal if the user hasn't performed any searches recently." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error verifying logs: $_"
    }
}

# Main execution
if (-not (Test-ExchangeOnlineConnection)) {
    Connect-ToExchangeOnline
}

try {
    Enable-ExpandedLogging -UserPrincipalName $UserPrincipalName
    Verify-LogsAreFlowing -UserPrincipalName $UserPrincipalName
}
catch {
    Write-Error "An error occurred: $_"
}
