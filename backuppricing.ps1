#Parameter section
[CmdletBinding()]
Param(
    [Parameter(HelpMessage = 'Define target Subscription ID')]
    [string]$subscriptionId,
    [Parameter(HelpMessage = 'Define target Subscriptionoffer https://azure.microsoft.com/en-us/support/legal/offer-details/')]
    [string]$subscriptionOffer = "MS-AZR-0003P",
    [Parameter(HelpMessage = 'Define the Target and Source LogAnalytics Workspace name for Azure Backup Logfiles')]
    [string]$Workspacename,
    [Parameter(HelpMessage = 'Define the Target and Source LogAnalytics Workspace ID for Azure Backup Logfiles')]
    [string]$WorkspaceID,
    [Parameter(HelpMessage = 'Define your Backupstorage sku (LRS/GRS)')]
    [boolean]$GRS = $true,
    [Parameter(HelpMessage = 'Provide preferred currency')]
    [string]$currency = "EUR",
    [Parameter(Mandatory = $false, HelpMessage = '[Optional Define a SPN to get access to pricelist and Azure Subscription. If nothing selected, the MSI will be used]')]
    [string]$ClientID,
    [Parameter(Mandatory = $false)]
    [string]$ClientSecret   
)

if (!($ClientID)) {
    $accessParams = @{
        ContentType = 'application/x-www-form-urlencoded'
        Headers     = @{
            'secret' = $ENV:MSI_SECRET
            'accept' = 'application/json'
        }
        Method      = 'GET'
        URI         = $ENV:MSI_ENDPOINT + "?resource=https://management.azure.com/&api-version=2017-09-01"
    } 
    $accessToken = Invoke-RestMethod @accessParams
}
else {
    $currentAzureContext = Get-AzureRmContext
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $accessToken = $token.AccessToken
    $authHeader = @{"Authorization" = "BEARER " + $accessToken } 
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

function get-VMConsumedStorage([string]$VMName, [string]$WorkspaceId, $subscriptionId, $authHeader, $Workspacename) {
    # get the consumed backup storage per VM
    $wrkspce = " https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.OperationalInsights/workspaces?api-version=2015-11-01-preview"
    $r = Invoke-WebRequest -Uri $wrkspce -Method GET -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    [string]$wrkspce = $clear.value.id | select-string ("$Workspacename")
    [array]$arr = $wrkspce.split("/")
    $WorkspaceRG = $arr[4]
    $url = "https://management.azure.com/subscriptions/$SubscriptionID/resourceGroups/$WorkspaceRG/providers/Microsoft.OperationalInsights/workspaces/$workspacename/api/query?api-version=2017-01-01-preview"
    #$query = 'AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "StorageAssociation" | summarize arg_max(TimeGenerated, *) by BackupItemUniqueId_s, StorageUniqueId_s | extend StorageInGB = todouble(StorageConsumedInMBs_s) / 1024 | project StorageInGB, BackupItemUniqueId_s, StorageUniqueId_s | join kind=inner (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "Storage" | distinct StorageUniqueId_s, StorageType_s | project StorageUniqueId_s, StorageType_s) on StorageUniqueId_s | project StorageInGB, BackupItemUniqueId_s, StorageType_s | join kind=leftouter (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "BackupItem" | distinct BackupItemUniqueId_s, BackupItemFriendlyName_s | project BackupItemUniqueId_s, BackupItemFriendlyName_s) on BackupItemUniqueId_s | project StorageInGB, BackupItemFriendlyName_s, BackupItemUniqueId_s, StorageType_s | where StorageType_s == "Cloud" | order by StorageInGB desc' 
    $body = @{query = 'AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "StorageAssociation" | summarize arg_max(TimeGenerated, *) by BackupItemUniqueId_s, StorageUniqueId_s | extend StorageInGB = todouble(StorageConsumedInMBs_s) / 1024 | project StorageInGB, BackupItemUniqueId_s, StorageUniqueId_s | join kind=inner (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "Storage" | distinct StorageUniqueId_s, StorageType_s | project StorageUniqueId_s, StorageType_s) on StorageUniqueId_s | project StorageInGB, BackupItemUniqueId_s, StorageType_s | join kind=leftouter (AzureDiagnostics | where Category == "AzureBackupReport" | where OperationName == "BackupItem" | distinct BackupItemUniqueId_s, BackupItemFriendlyName_s | project BackupItemUniqueId_s, BackupItemFriendlyName_s) on BackupItemUniqueId_s | project StorageInGB, BackupItemFriendlyName_s, BackupItemUniqueId_s, StorageType_s | where StorageType_s == "Cloud" | order by StorageInGB desc' } | ConvertTo-Json
    #= $query | ConvertTo-Json
    $webresults = Invoke-WebRequest -Uri $url -Method post -Headers $authHeader -Body $body -ContentType "application/json"
    $resultsTable = $webresults.Content | ConvertFrom-Json
    $resultsTable.tables.rows | % {
        [string]$str = $resultsTable.tables.rows | select-string -pattern $VMName
        [array]$arr = $str.split("")
    }  
    $VMConsumedStorage = $arr[0] 
    return $VMConsumedStorage
}

function get-vmstatus([string]$VMname, [string]$ResourceGroupName, [string]$subscriptionId, $authHeader) {
    $vmuri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$VMname/instanceView?api-version=2018-06-01"
    $r = Invoke-WebRequest -Uri $vmuri -Method GET -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    $VMStats = $clear.statuses | where { ($_.code -eq "PowerState/running") -and ($_.displaystatus -eq "VM running") }
    if ($VMStats) {
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
function send-data([string]$WorkspaceId, [string]$Workspacename, $logMessage, $authHeader) {
    # get workspace secret
    $dateTime = get-date
    if ($dateTime.kind.tostring() -ne 'Utc') {
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message $dateTime
    }
    $logType = "BackupBillingReworked"
    $wrkspce = " https://management.azure.com/subscriptions/$SubscriptionID/providers/Microsoft.OperationalInsights/workspaces?api-version=2015-11-01-preview"
    $r = Invoke-WebRequest -Uri $wrkspce -Method GET -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    [string]$wrkspce = $clear.value.id | select-string ("$Workspacename")
    [array]$arr = $wrkspce.split("/")
    $WorkspaceRG = $arr[4]
    $workspacekeyurl = "https://management.azure.com/subscriptions/$subscriptionID/resourcegroups/$WorkspaceRG/providers/Microsoft.OperationalInsights/workspaces/$workspacename/sharedKeys?api-version=2015-11-01-preview"
    $r = Invoke-WebRequest -Uri $workspacekeyurl -Method POST -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json
    $WorkspaceKey = $clear.primarySharedKey
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
# get all VM's from all RSV per subscription
$vaulturi = "https://management.azure.com/subscriptions/$subscriptionid/providers/Microsoft.RecoveryServices/vaults?api-version=2016-06-01"
$r = Invoke-WebRequest -Uri $vaulturi -Method GET -Headers $authHeader
$clear = $r.Content | ConvertFrom-Json
$Vaults = $clear.value
$Vaults | % {
    $BareVMOnboardingRate = 0
    $VMConsumedStorage = 0
    $VMStorageRate = 0
    $clear.value.ID | % {
        $RSVRG = $_.split("/")
        $RSVRG = $RSVRG[4]
    }
    # get RSV region 
    $vaultregion = $_.Location

    # get all VM's that are onboarded to the Vault
    $RSV = $_.Name
    $filter1 = "'AzureIaasVM'"
    $filter2 = "'VM'" 
    $VMs = 'https://management.azure.com/Subscriptions/' + $subscriptionid + '/resourceGroups/' + $RSVRG + '/providers/Microsoft.RecoveryServices/vaults/' + $RSV + '/backupProtectedItems?api-version=2017-07-01&$filter=backupManagementType eq ' + $filter1 + ' and itemType eq ' + $filter2 + ''
    $r = Invoke-WebRequest -Uri $VMs -Method GET -Headers $authHeader
    $clear = $r.Content | ConvertFrom-Json

    $VMs = $clear.value.properties
    if ($VMs) {
        $VMs | % {
            $Result = @{ }
            # get pricing information depending on location of RSV
            [decimal]$BareVMOnboardingRate = get-OnboardedVMprice -vaultregion $vaultregion
            [decimal]$VMStorageRate = get-VMStoragePrice -vaultregion $vaultregion -GRS $GRS
            # get resource group of vm
            $VMname = $_.friendlyname
            $RG = $_.sourceResourceID.split("/")
            $RG = $RG[4]


            # get total size of virtual machine
            # check if vm is running
            $VMStatus = get-vmstatus -VMname $VMname -ResourceGroupName $RG -subscriptionId $subscriptionid -authHeader $authHeader
            if ($VMstatus -eq "online") {
                $vmuri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/" + $VMname + "?api-version=2018-06-01"
                $r = Invoke-WebRequest -Uri $vmuri -Method GET -Headers $authHeader    
                $clear = $r.Content | ConvertFrom-Json        
                $OSDisk = $clear.properties.storageProfile.osDisk.diskSizeGB
                $DataDisk = $clear.properties.storageProfile.dataDisks.DiskSizeGB
            
                # calculate the overall size of VM
                $OverAllDiskSize = $OSDisk + $DataDisk
            }
            else {
                $vmuri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/" + $VMname + "?api-version=2018-06-01"
                $r = Invoke-WebRequest -Uri $vmuri -Method GET -Headers $authHeader    
                $VMclear = $r.Content | ConvertFrom-Json   
                $OSdiskname = $VMclear.properties.storageProfile.osDisk.name
                $Datadiskname = $VMclear.properties.storageProfile.dataDisk.name          

                $vmuri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$RG/providers/Microsoft.Compute/disks?api-version=2018-06-01"
                $r = Invoke-WebRequest -Uri $vmuri -Method GET -Headers $authHeader
                $clear = $r.Content | ConvertFrom-Json           

                # get disk size
                $OSDisk = ($clear.value | where name -eq "$OSdiskname").properties.diskSizeGB
                $DataDisk = ($clear.value | where name -eq "$Datadiskname").properties.diskSizeGB

                # calculate the overall size of VM
                $OverAllDiskSize = 0
                $OverAllDiskSize = $OSDisk + $DataDisk           
                                     
            }
            # get costcenter tag
            $vmuri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/" + $VMname + "?api-version=2018-06-01"
            $r = Invoke-WebRequest -Uri $vmuri -Method GET -Headers $authHeader    
            $clear = $r.Content | ConvertFrom-Json 
            $CostCenter = $clear.tags.CostCenter

            # get consumed RSV storage by VM
            $VMConsumedStorage = get-VMConsumedStorage -VMName $VMname -WorkspaceId $WorkspaceID -authHeader $authHeader -Workspacename $Workspacename -subscriptionId $subscriptionid

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

            $OverallPrice = [math]::Round($OverallPrice, 3)

            $Result = @"
[{  "VirtualMachine": "$VMname",
    "CostCenter": $CostCenter,
    "ConsumedStorage": $VMConsumedStorage,
    "BackupCosts($currency)": "$OverallPrice",
}
"@

            # create Hashtable 
            #$Result.Add("$_", $OverallPrice)  
            #$logMessage = ConvertTo-Json $Result
            send-data -WorkspaceId $WorkspaceID -Workspacename $Workspacename -logMessage $Result -authHeader $authHeader

            Write-Output "VM: $VMname // Price: $OverallPrice // BarePrice: $BareVMOnboardingRate // Disksize: $OverAllDiskSize // ConsumedStorage: $VMConsumedStorage"
        }
    }
    
}
$Result
