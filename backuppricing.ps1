#Parameter section
[CmdletBinding()]
Param(
    [Parameter(HelpMessage = 'Define target Subscription ID')]
    [string]$subscriptionId = "690ad0dc-4ba7-4d77-837d-db32c3a44be7",
    [Parameter(HelpMessage = 'Define target Subscriptionoffer https://azure.microsoft.com/en-us/support/legal/offer-details/')]
    [string]$subscriptionOffer = "MS-AZR-0003P",
    [Parameter(HelpMessage = 'Define the Target and Source LogAnalytics Workspace name for Azure Backup Logfiles')]
    [string]$Workspacename = "BackupLogAnalytics8772",
    [Parameter(HelpMessage = 'Define the Target and Source LogAnalytics Workspace ID for Azure Backup Logfiles')]
    [string]$WorkspaceID = "9d6e2e1e-0f35-4a75-a9fe-cad6b217bd54",
    [Parameter(HelpMessage = 'Define your Backupstorage sku (LRS/GRS)')]
    [boolean]$GRS = $true,
    [Parameter(HelpMessage = 'Provide preferred currency')]
    [string]$currency = "EUR",
    [Parameter(Mandatory = $false, HelpMessage = '[Optional Define a SPN to get access to pricelist and Azure Subscription]')]
    [string]$ClientID,
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret   
)

#$rmAccount = Add-AzureRmAccount -SubscriptionId $subscriptionId | Select-AzureRmSubscription
if (!($ClientID)) {
    $currentAzureContext = Get-AzureRmContext
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $accessToken = $token.AccessToken
}
# getting all azure price information - this can take a while
$authHeader = @{"Authorization" = "BEARER " + $accessToken } 
$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Commerce/RateCard?api-version=2016-08-31-preview&`$filter=OfferDurableId%20eq%20'" + $subscriptionOffer + "'%20and%20Currency%20eq%20'" + $currency + "'%20and%20Locale%20eq%20'en-US'%20and%20RegionInfo%20eq%20'DE'"
$r = Invoke-WebRequest -Uri $uri -Method GET -Headers $authHeader
$price = $r.Content | ConvertFrom-Json

# get price information for each onboarded VM
function get-OnboardedVMprice([string]$vaultregion) {

    $region = switch ($vaultregion) {
        "westeurope" { "EU West" }
        "northeurope" { "EU North" }      
    }
    if (!(($price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "Azure VM and on-premises Server Protected Instances") }).MeterRegion.contains($region))) {
        $region = ""
    }

    $BareVMOnboardingRate = $price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "Azure VM and on-premises Server Protected Instances") -and ($_.MeterRegion -eq $region) }
    $BareVMOnboardingRate = $BareVMOnboardingRate.MeterRates -split '@{0='
    $BareVMOnboardingRate = $BareVMOnboardingRate[1] -split '}'
    $BareVMOnboardingRate = $BareVMOnboardingRate[0] 
    return $BareVMOnboardingRate
}


# get the price information per GB for each VM
function get-VMStoragePrice ([string]$vaultregion, [boolean]$GRS) {

    $region = switch ($vaultregion) {
        "westeurope" { "EU West" }
        "northeurope" { "EU North" }      
    }

    if ($GRS) {
        if (!(($price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "GRS Data Stored") }).MeterRegion.contains($region))) {
            $region = ""
        }
        $VMStorageRate = $price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "GRS Data Stored") -and ($_.MeterRegion -eq $region) }
        $VMStorageRate = $VMStorageRate.MeterRates -split '@{0='
        $VMStorageRate = $VMStorageRate[1] -split '}'
        $VMStorageRate = $VMStorageRate[0]
    }
    else {
        if (!(($price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "LRS Data Stored") }).MeterRegion.contains($region))) {
            $region = ""
        }
        $VMStorageRate = $price.meters | Where-Object { ($_.Metercategory -eq "Backup") -and ($_.MeterName -eq "LRS Data Stored") -and ($_.MeterRegion -eq $region) }
        $VMStorageRate = $VMStorageRate.MeterRates -split '@{0='
        $VMStorageRate = $VMStorageRate[1] -split '}'
        $VMStorageRate = $VMStorageRate[0]
    }
    return $VMStorageRate
}

function get-VMConsumedStorage([string]$VMName, [string]$WorkspaceId) {
    # get the consumed backup storage per VM
    $query = 'AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "StorageAssociation" | summarize arg_max(TimeGenerated, *) by BackupItemUniqueId_s, StorageUniqueId_s | extend StorageInGB = todouble(StorageConsumedInMBs_s) / 1024 | project StorageInGB, BackupItemUniqueId_s, StorageUniqueId_s | join kind=inner (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "Storage" | distinct StorageUniqueId_s, StorageType_s | project StorageUniqueId_s, StorageType_s) on StorageUniqueId_s | project StorageInGB, BackupItemUniqueId_s, StorageType_s | join kind=leftouter (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "BackupItem" | distinct BackupItemUniqueId_s, BackupItemFriendlyName_s | project BackupItemUniqueId_s, BackupItemFriendlyName_s) on BackupItemUniqueId_s | project StorageInGB, BackupItemFriendlyName_s, BackupItemUniqueId_s, StorageType_s | where StorageType_s == "Cloud" | order by StorageInGB desc'
    $ConsumedStorageInGB = Invoke-AzureRmOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $query
    $ConsumedStorageInGB = $ConsumedStorageInGB.Results 
    $VMConsumedStorage = $ConsumedStorageInGB | where BackupItemFriendlyName_s -eq $VMName
    $VMConsumedStorage = $VMConsumedStorage.StorageInGB
    return $VMConsumedStorage
}

function get-vmstatus([string]$VMname, [string]$ResourceGroupName) {
    $VMStats = (Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $VMname -Status).Statuses
    $VMStats = ($VMStats | Where Code -Like 'PowerState/*')[0].DisplayStatus
    if ($VMStats -eq "VM running") {
        return "online"
    }
    else {
        return "offline"
    }
}

function Build-signature ($CustomerID, $SharedKey, $Date, $ContentLength, $method, $ContentType, $resource) {
    $xheaders = 'x-ms-date:' + $Date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($SharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.key = $keyBytes
    $calculateHash = $sha256.ComputeHash($bytesToHash)
    $encodeHash = [convert]::ToBase64String($calculateHash)
    $authorization = 'SharedKey {0}:{1}' -f $CustomerID, $encodeHash
    return $authorization
}
function send-data([string]$WorkspaceId, [string]$Workspacename, $logMessage) {
    # get workspace secret
    $dateTime = get-date
    if ($dateTime.kind.tostring() -ne 'Utc') {
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message $dateTime
    }
    $logType = "BackupBillingReworked"
    $WorkspaceRG = (get-azurermresource | where ResourceID -like "*$workspacename*").ResourceGroupName
    $WorkspaceKey = (Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $workspaceRG[0] -Name $Workspacename).PrimarySharedKey
    $body = ([System.Text.Encoding]::UTF8.GetBytes($logMessage))
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $WorkspaceId `
        -sharedKey $WorkspaceKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $dateTime;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing 
    return $response.StatusCode
}

# get all VM's from all RSV per subscription
$Vaults = Get-AzureRmRecoveryServicesVault
$Vaults | % {
    $BareVMOnboardingRate = 0
    $VMConsumedStorage = 0
    $VMStorageRate = 0
    Get-AzureRmRecoveryServicesVault -ResourceGroupName $_.ResourceGroupName -Name $_.Name | Set-AzureRmRecoveryServicesVaultContext
    # get RSV region 
    $vaultregion = $_.Location

    # get all VM's that are onboarded to the Vault
    $VMs = Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM
    $VMs = $VMs.FriendlyName

    $VMs | % {
        $Result = @{ }
        # get pricing information depending on location of RSV
        [decimal]$BareVMOnboardingRate = get-OnboardedVMprice -vaultregion $vaultregion
        [decimal]$VMStorageRate = get-VMStoragePrice -vaultregion $vaultregion -GRS $GRS
        # get resource group of vm
        $RG = (Get-AzureRmResource -Name $_) | where ResourceType -eq "Microsoft.Compute/virtualMachines"
        $RG = $RG.ResourceGroupName


        # get total size of virtual machine
        # check if vm is running
        $VMStatus = get-vmstatus -VMname $_ -ResourceGroupName $RG
        Write-Output "$VMStatus"
        if ($VMstatus -eq "online") {
            $OSDisk = (((Get-AzureRmVM -ResourceGroupName $RG -Name $_).StorageProfile).Osdisk).DiskSizeGB
            $DataDisk = (((Get-AzureRmVM -ResourceGroupName $RG -Name $_).StorageProfile).DataDisks).DiskSizeGB

            # calculate the overall size of VM
            $OverAllDiskSize = $OSDisk + $DataDisk
        }
        else {
            $tmp = (Get-azurermdisk -resourcegroupname $RG | where ManagedBy -like "*$_*").DiskSizeGB
            $OverAllDiskSize = 0
            $tmp | % { $OverAllDiskSize += $_ }           
                    
        }
        # get consumed RSV storage by VM
        $VMConsumedStorage = get-VMConsumedStorage -VMName $_ -WorkspaceId $WorkspaceID

        # check if VM is <= 50 GB or => 500 GB to get the accurate basic backup price
        if ($OverAllDiskSize -le 50) {
            $BareVMOnboardingRate = $BareVMOnboardingRate / 2
        }
        if ($OverAllDiskSize -ge 500) {
            [double]$factor = $OverAllDiskSize / 500
            $factor = [int][Math]::Ceiling($factor)
            # calculate the final onboarding price
            $BareVMOnboardingRate = $BareVMOnboardingRate * $factor
        }
        
        # calculate pricing for RSV storage per GB
        $VMStorageRate = ($VMStorageRate) * ($VMConsumedStorage)

        # calculate the overall price for VM
        $OverallPrice = $VMStorageRate + $BareVMOnboardingRate

        # create Hashtable 
        $Result.Add("$_", $OverallPrice)  
        $logMessage = ConvertTo-Json $Result
        send-data -WorkspaceId $WorkspaceID -Workspacename $Workspacename -logMessage $logMessage

        Write-Output "VM: $_ // Price: $OverallPrice // BarePrice: $BareVMOnboardingRate // Disksize: $OverAllDiskSize // ConsumedStorage: $VMConsumedStorage"
    }
    
}




