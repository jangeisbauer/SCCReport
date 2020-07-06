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
# 
# Credits to: https://github.com/ssugar/Blog/blob/c34608c3165023d35c65f08899c7ef18b711460c/PowerBIUsage/Scripts/Get-PowerBIUsage.ps1
# #########################################################################################################################################
# Variables
# Set how many days from today you want to report backward
# Default "-1" --> report last 24 hours
$DaysBack = -1
# tenant name of KeyVault 
$tenantNameKV = "tenant.com"
# set app details / get secret
$appId = '533242343245'
$tenantId = 'a3423423424bf'
$domain = 'tenant.com' #office atp target tenant
# get secret from azure key vault 
# connect to azure
Connect-AzureRmAccount -Tenant $tenantNameKV
$clientSecret = (Get-AzureKeyVaultSecret -vaultName "keyvault" -name "key").SecretValueText
# #########################################################################################################################################


# #########################################################################################################################################
# O365 Management API Functions
# #########################################################################################################################################
function Get-MgmtAccessToken($appId, $domain, $clientSecret) {
    $resource = 'https://manage.office.com' 
    $clientSecret = [uri]::EscapeDataString($clientSecret)
    $uri = "https://login.windows.net/{0}/oauth2/token" -f $domain
    $body = "grant_type=client_Credentials&resource=$resource&client_id=$appId&client_secret=$clientSecret"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -Method "POST"
    $AccessToken = $response.access_token
    return $AccessToken
}
function New-AuditLogSubscription( $tenantId, $AccessToken) {
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/start?contentType=Audit.General&PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "POST"
    return $response
}
function Stop-AuditLogSubscription( $tenantId, $AccessToken) {
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/stop?contentType=Audit.General&PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "POST"
    return $response
}
function Get-AuditLogSubscriptions( $tenantId, $AccessToken) {
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/list?PublisherIdentifier=$($tenantId)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogSubscriptionContent( $tenantId, $AccessToken, $startTime, $endTime ) {
    $uri = "https://manage.office.com/api/v1.0/$($tenantId)/activity/feed/subscriptions/content?contentType=Audit.General&startTime=$($startTime)&endTime=$($endTime)"
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogSubscriptionContentBlob( $tenantId, $contentUri, $AccessToken ) {
    $uri = $contentUri
    $response = Invoke-RestMethod -Uri $uri -ContentType "application/x-www-form-urlencoded" -Headers @{'authorization'="Bearer $($AccessToken)"} -Method "GET"
    return $response
}
function Get-AuditLogEntries( $tenantId, $AccessToken, $startTime, $endTime) {
    $Content = Get-AuditLogSubscriptionContent -tenantId $tenantId -AccessToken $AccessToken -startTime $startTime -endTime $endTime
    $allBlobContent = @()
    foreach($item in $Content){
        $blobContent = Get-AuditLogSubscriptionContentBlob -tenantId $tenantId -AccessToken $AccessToken -contentUri $($item.contentUri)
        $allBlobContent += $blobContent
    }
    return $allBlobContent
}

$AccessToken = Get-MgmtAccessToken -appId $appId -domain $domain -clientSecret $clientSecret
New-AuditLogSubscription -tenantId $tenantId -AccessToken $AccessToken

$endTime = Get-Date
$endTimeString = Get-Date $endTime.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss"
$startTime = ($endTime.ToUniversalTime()).AddDays($DaysBack)
$startTimeString = Get-Date $startTime -Format "yyyy-MM-ddTHH:mm:ss"

write-host "Retrieving log entries created between $startTimeString and $endTimeString (if you have choosen too many days to report, go, grab a coffee)"

# Results
$Entries = Get-AuditLogEntries -tenantId $tenantId -AccessToken $AccessToken -startTime $startTimeString -endTime $endTimeString
$allInvestigations = $Entries | Where-Object{$_.investigationname -ne $null}
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

# don't know if this is neccessary ... anyway
Stop-AuditLogSubscription -tenantId $tenantId -AccessToken $AccessToken

write-host "done."