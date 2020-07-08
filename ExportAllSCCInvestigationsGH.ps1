 # #########################################################################################################################################
# 
# Report All Investigations in Security & Compliance Center and export to CSV
# 
# - Uses O365 Management API
# - Uses Client-Secret in Azure Key Vault (to gain access, you need to add somebody to the access policy)
# - You need to 'install-module azurerm' upfront
#
# Version: 0.1 (2020-5-25)
# Author: @janvonkirchheim
# Version: 0.2 (2020-7-08)
# Author: @marcoscheel
# Credits to: https://github.com/ssugar/Blog/blob/c34608c3165023d35c65f08899c7ef18b711460c/PowerBIUsage/Scripts/Get-PowerBIUsage.ps1
# #########################################################################################################################################
# Variables

#use keyvault or get secret per Read-Host (for debugging)
$useKeyVault = $true;

#specify start and and date attention: only 7 days back are possible! as documentent for start and end toime here: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#list-available-content 
$startTime = [System.DateTime]::UtcNow; #start now #TODO
$endTime = $startTime.AddHours(-24);#move 24 hour back #TODO

# after az login check with this command for tenant id and subscription id: Get-AzSubscription
$tenantId = "55ccd7c0-7dd0-414c-8fbb-a8469c7dde2d" #TODO
$subscriptionId = "bbb7594a-30e2-4928-9631-0588321da565" #TODO
#kevault
$keyvaultname = "prd-DGKM-mgmntapi-weu-kv" #TODO
$keyvaultsecretname = "AADClientSecret" #TODO

# AAD application id matching the secret to use for auth
$appId = "bc86c145-3d2f-435a-9293-39832c7ceb59" #TODO

#static
$workIntervall = 1; #in hours
$mgmtSubscriptionWorkload = "Audit.General";
$mgmtAuditLogRecordType = 64; # AirInvestigation = Automated incident response (AIR) events. https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype


# #########################################################################################################################################
# get secret from azure key vault 
# connect to azure
$clientSecret = "NOTYETSET";
if ($useKeyVault)
{
    #check for az modules
    $AzAccountsPsm = Get-Module -Name Az.Accounts -ListAvailable;
    $AzKeyVaultPsm = Get-Module -Name Az.KeyVault -ListAvailable;
    if ($null -eq $AzAccountsPsm -or $null -eq $AzKeyVaultPsm){
        Write-Host "Your are missing modules. Install Az Module (needed: Install-Module Az.Accounts + Install-Module Az.KeyVault" -ForegroundColor Red;
        exit;
    }
    else{
        Import-Module -Name Az.Accounts;
        Import-Module -Name Az.KeyVault;
    }
    $isloggedin = Get-AzContext -ListAvailable | Where-Object { $_.Tenant.Id -eq $tenantId -and $_.Subscription.Id -eq $subscriptionId };
    if ($null -eq $isloggedin){
        #use device authentication to reuse previously authenticated sessions
        Login-AzAccount -UseDeviceAuthentication -TenantId $tenantId -Subscription $subscriptionId ;
    }
    $clientSecret = (Get-AzKeyVaultSecret -VaultName $keyvaultname -Name $keyvaultsecretname).SecretValueText;
}
else{
    $clientSecret = Read-Host "Enter client secret for app id: $appId";
}
# #########################################################################################################################################

$currentAccessToken = "NOTYETSET";
$currentAccessTokenExpiration = [System.DateTime]::UtcNow;
$origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0

# #########################################################################################################################################
# O365 Management API Functions
# #########################################################################################################################################
<#
.SYNOPSIS
Get an access token and renew if needed

.DESCRIPTION
Get an access token from the V1 AAD endpoint. Access tokens are only valid (by default for 60 minutes)

.EXAMPLE
https://docs.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis
#>
function Get-MgmtAccessToken() {
    if ($currentAccessTokenExpiration -lt [System.DateTime]::UtcNow){
        $resource = "https://manage.office.com";
        $encodedClientSecret = [uri]::EscapeDataString($clientSecret);
        $uri = "https://login.microsoftonline.com/$tenantId/oauth2/token";
        $body = "grant_type=client_Credentials&resource=$resource&client_id=$appId&client_secret=$encodedClientSecret"
        $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -Method "POST"
        $currentAccessToken = $response.access_token
        $currentAccessTokenExpiration = $origin.AddSeconds($response.expires_on)
    }
    return $currentAccessToken;
}
function New-AuditLogSubscription() {
    $AccessToken = Get-MgmtAccessToken;
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/start?contentType=$mgmtSubscriptionWorkload&PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "POST"
    return $response
}
function Stop-AuditLogSubscription() {
    $AccessToken = Get-MgmtAccessToken;
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/stop?contentType=$mgmtSubscriptionWorkload&PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "POST"
    return $response
}
function Get-AuditLogSubscriptions() {
    $AccessToken = Get-MgmtAccessToken;
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/list?PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogSubscriptionContent($start, $end ) {
    $AccessToken = Get-MgmtAccessToken;
    #logically teh script is doing a count down (start is more current and end is in the past), but the API is working more logical (start will be earlier than end) so we switch here
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/content?contentType=$mgmtSubscriptionWorkload&startTime=$($end)&endTime=$($start)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogSubscriptionContentBlob($contentUri) {
    $AccessToken = Get-MgmtAccessToken;
    $uri = $contentUri
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogEntries($start, $end) {
    $dateFormat = "yyyy-MM-ddTHH:mm";
    $Content = Get-AuditLogSubscriptionContent -start $start.ToString($dateFormat) -end $end.ToString($dateFormat)
    $allBlobContent = @()
    foreach($item in $Content){
        $blobContent = Get-AuditLogSubscriptionContentBlob -contentUri $($item.contentUri)
        $allBlobContent += $blobContent
    }
    return $allBlobContent
}

Write-Host "Check if a subscription for workload $mgmtSubscriptionWorkload is already started";
$currentsubs = Get-AuditLogSubscriptions | Where-Object {$_.contentType -eq $mgmtSubscriptionWorkload -and $_.status -eq "enabled"}
if ($null -eq $currentsubs){
    Write-Host "Setup new subscription for workload $mgmtSubscriptionWorkload";
    New-AuditLogSubscription
    #read more here regaring availability of content: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#stop-a-subscription
    Write-Host "Setup new subscription for workload $mgmtSubscriptionWorkload setup! Attention: Normaly it takes about 24 hour to fill with content!" -ForegroundColor Yellow;
} 
else{
    Write-Host "Subscription for workload $mgmtSubscriptionWorkload is already setup";
}

#List available content states that one should only return content from max 24 hours
#https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#list-available-content
#To report more work in 24 hour chunks
write-host "Retrieving log entries created between $startTime and $endTime (if you have choosen too many days to report, go, grab a coffee)"

$currentEnd = $startTime.AddHours($workIntervall * -1);
$currentStart = $startTime;
$Entries = @();
while ($currentStart -gt $endTime) {
    if ($currentEnd -lt $endTime){
        $currentEnd = $endTime; # if current end (due to intervall) is smaller then desired end, set the desired end to not overquery ;)
    }
    $Entries += Get-AuditLogEntries -start $currentStart -end $currentEnd
    $currentStart = $currentEnd;
    $currentEnd = $currentStart.AddHours($workIntervall * -1);
}

# Results
$allInvestigations = $Entries | Where-Object{ $_.RecordType -eq $mgmtAuditLogRecordType -and $_.InvestigationName -ne $null}
$allCustomInvestigations = @()

# Looping through the results and join them together to get a nice overview
foreach($investigation in $allInvestigations)
{
    $myInvestigation = new-object psobject
    $data = $investigation.data | convertfrom-json
    $allEntities = $data | Select-Object -ExpandProperty entities 
    $1stEntity = ""
    foreach($entity in $allEntities)
    {
        if(($entity | gm).Name.Contains("SenderIP"))
        {
            $1stEntity = $allEntities | ?{$_.'$id' -eq $entity.'$id'}
        }
    }
    if($1stEntity -eq "")
    {
        $1stEntity = $allEntities | ?{$_.'$id' -eq "2"}
    }
    $myInvestigation | add-member Noteproperty CreationTime $investigation.CreationTime
    $myInvestigation | add-member Noteproperty id $investigation.id
    $myInvestigation | add-member Noteproperty InvestigationName $investigation.InvestigationName
    $myInvestigation | add-member Noteproperty InvestigationType $investigation.InvestigationType
    $myInvestigation | add-member Noteproperty Status $investigation.Status
    $myInvestigation | add-member Noteproperty Recipient $1stEntity.Recipient
    $myInvestigation | add-member Noteproperty Subject $1stEntity.Subject
    $customUrl = ""
    foreach($url in $1stEntity.Urls)
    {
        $customUrl += $url + ";"
    }
    $myInvestigation | add-member Noteproperty Urls $customUrl
    $myInvestigation | add-member Noteproperty Threats $1stEntity.Threats
    $myInvestigation | add-member Noteproperty Sender $1stEntity.Sender
    $myInvestigation | add-member Noteproperty P1Sender $1stEntity.P1Sender
    $myInvestigation | add-member Noteproperty P1SenderDomain $1stEntity.P1SenderDomain
    $myInvestigation | add-member Noteproperty SenderIP $1stEntity.SenderIP
    $myInvestigation | add-member Noteproperty P2Sender $1stEntity.P2Sender
    $myInvestigation | add-member Noteproperty P2SenderDisplayName $1stEntityP2SenderDisplayName
    $myInvestigation | add-member Noteproperty P2SenderDomain $1stEntity.P2SenderDomain
    $myInvestigation | add-member Noteproperty ReceivedDate $1stEntity.ReceivedDate
    $myInvestigation | add-member Noteproperty DeliveryAction $1stEntity.DeliveryAction
    $myInvestigation | add-member Noteproperty DeliveryLocation $1stEntity.DeliveryLocation
    $DeepLinkUrlAsHL = "=HYPERLINK(`"" + $investigation.DeepLinkUrl + "`")"
    $myInvestigation | add-member Noteproperty DeepLinkUrl $DeepLinkUrlAsHL
    $AlertUrlAsHL = "=HYPERLINK(`"" + $data.ExtendedLinks.href + "`")"
    $myInvestigation | add-member Noteproperty AlertUrl $AlertUrlAsHL
    $AlertID = $data.ExtendedLinks.href.split('=')[1]
    $myInvestigation | add-member Noteproperty AlertID $AlertID

    #build the array
    $allCustomInvestigations += $myInvestigation 
}

# write the output csv
$fileName = $(get-date -f yyyy-MM-dd) + "-SCC-InvestigationsExport.csv"
$allCustomInvestigations | ConvertTo-Csv > $fileName

Write-Host "The current subscription for workload $mgmtSubscriptionWorkload will NOT be stopped. If you stop a subscription any events created until a restart will be lost!" -ForegroundColor Yellow;
#Read more: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference#stop-a-subscription
#Stop-AuditLogSubscription

write-host "done."