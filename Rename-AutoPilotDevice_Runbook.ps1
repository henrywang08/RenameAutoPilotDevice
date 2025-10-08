<#
.SYNOPSIS
    Renames AutoPilot devices - Final Azure Automation Runbook Version.

.DESCRIPTION
    This script is designed to run as an Azure Automation Runbook using Managed Identity.
    It reads configuration from Azure Automation Variables.

.NOTES
    Author: AutoPilot Management Team
    Version: 4.0 - Final Azure Automation Runbook
    
    IMPORTANT: This script must be run as an Azure Automation Runbook, not locally.
    The Managed Identity must have the following Graph API permissions:
    - DeviceManagementManagedDevices.ReadWrite.All
    - Device.Read.All
    - User.Read.All
    - Group.Read.All
    - GroupMember.Read.All
    - Application.ReadWrite.All
#>

# Load required assemblies
Add-Type -AssemblyName System.Web

# Import required modules for Azure Automation
try {
    Write-Output "Importing Azure PowerShell modules..."
    Import-Module Az.Accounts -Force
    Write-Output "Successfully imported Az.Accounts module"
}
catch {
    Write-Error "Failed to import Az.Accounts module: $($_.Exception.Message)"
    throw
}

# Helper function to get configuration from Azure Automation Variables (runbook environment)
function Get-AutomationVariableSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue = $null,
        
        [Parameter(Mandatory = $false)]
        [switch]$Required
    )
    
    try {
        # This will only work in Azure Automation runbook environment
        $value = Get-AutomationVariable -Name $Name -ErrorAction SilentlyContinue
        if ($value) {
            Write-Verbose "Retrieved automation variable '$Name': $value"
            return $value
        }
    }
    catch {
        Write-Verbose "Could not retrieve automation variable '$Name': $($_.Exception.Message)"
    }
    
    # Use default value if provided
    if ($null -ne $DefaultValue) {
        Write-Verbose "Using default value for '$Name': $DefaultValue"
        return $DefaultValue
    }
    
    # If required and no value found, throw error
    if ($Required) {
        $errorMessage = "❌ Required automation variable '$Name' not found and no default provided"
        Write-Error $errorMessage
        throw $errorMessage
    }
    
    return $null
}

# Load configuration from Azure Automation Variables
Write-Output "=== Loading Configuration from Azure Automation Variables ==="
Write-Output ""

try {
    # Load each configuration value
    $tenantId = Get-AutomationVariableSafe -Name "AutoPilot-TenantId" -Required
    $groupId = Get-AutomationVariableSafe -Name "AutoPilot-GroupId" -Required
    $devicePrefix = Get-AutomationVariableSafe -Name "AutoPilot-DevicePrefix" -DefaultValue "CMA"
    $maxNameLengthStr = Get-AutomationVariableSafe -Name "AutoPilot-MaxNameLength" -DefaultValue "15"
    $enableRebootStr = Get-AutomationVariableSafe -Name "AutoPilot-EnableReboot" -DefaultValue "true"
    $verboseLoggingStr = Get-AutomationVariableSafe -Name "AutoPilot-VerboseLogging" -DefaultValue "false"
    
    # Convert types safely
    $maxNameLength = [int]([string]$maxNameLengthStr)
    $enableReboot = [System.Convert]::ToBoolean([string]$enableRebootStr)
    $verboseLogging = [System.Convert]::ToBoolean([string]$verboseLoggingStr)
    
    $Script:Config = @{
        TenantId = $tenantId
        GroupId = $groupId
        DeviceNamePrefix = $devicePrefix
        MaxDeviceNameLength = $maxNameLength
        EnableReboot = $enableReboot
        VerboseLogging = $verboseLogging
        GraphBaseUri = "https://graph.microsoft.com"
    }

    Write-Output "✓ Configuration loaded successfully from Azure Automation Variables:"
    Write-Output "  Tenant ID: $($Script:Config.TenantId)"
    Write-Output "  Group ID: $($Script:Config.GroupId)"
    Write-Output "  Device Prefix: $($Script:Config.DeviceNamePrefix)"
    Write-Output "  Max Name Length: $($Script:Config.MaxDeviceNameLength)"
    Write-Output "  Enable Reboot: $($Script:Config.EnableReboot)"
    Write-Output "  Verbose Logging: $($Script:Config.VerboseLogging)"
    Write-Output ""
}
catch {
    Write-Error "Configuration failed: $($_.Exception.Message)"
    throw
}

function New-DeviceName {
    <#
    .SYNOPSIS
        Generates a new device name based on country code.
    .DESCRIPTION
        Creates device names in format: CMA{CountryCode}-{OriginalSuffix}
        Ensures the name doesn't exceed the maximum length limit.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OriginalDeviceName,
        
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Z]{2}$')]
        [string]$CountryCode
    )

    Write-Verbose "Generating new device name for '$OriginalDeviceName' with country code '$CountryCode'"

    # Check if device name already contains country code in expected format
    $expectedPrefix = "$($Script:Config.DeviceNamePrefix)-$CountryCode-"
    if ($OriginalDeviceName -match "^$($Script:Config.DeviceNamePrefix)-$CountryCode-") {
        Write-Verbose "Device '$OriginalDeviceName' already has correct country prefix"
        return $OriginalDeviceName
    }

    # Extract the suffix from original name - handle existing CMA- prefix
    $suffix = $OriginalDeviceName
    if ($OriginalDeviceName -match "^CMA-(.+)$") {
        $suffix = $Matches[1]
    } elseif ($OriginalDeviceName.Length -gt 4) {
        $suffix = $OriginalDeviceName.Substring(4)
    }
    
    $newName = "$expectedPrefix$suffix"

    # Trim to maximum length if necessary
    if ($newName.Length -gt $Script:Config.MaxDeviceNameLength) {
        $newName = $newName.Substring(0, $Script:Config.MaxDeviceNameLength)
        Write-Warning "Device name truncated to $($Script:Config.MaxDeviceNameLength) characters: $newName"
    }

    Write-Verbose "Generated new device name: '$newName'"
    return $newName
}

function Rename-Device {
    <#
    .SYNOPSIS
        Renames a managed device using Microsoft Graph API.
    .DESCRIPTION
        Finds the device by name in Intune, renames it, and initiates a reboot.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OriginalDeviceName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$NewName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken
    )

    if ($OriginalDeviceName -eq $NewName) {
        Write-Output "Device '$OriginalDeviceName' already has the desired name. No rename needed."
        return
    }

    Write-Verbose "Starting rename process for device '$OriginalDeviceName' to '$NewName'"

    try {
        # Get device ID from Graph API using device name
        $deviceId = Get-IntuneDeviceId -DeviceName $OriginalDeviceName -AccessToken $AccessToken
        
        # Rename device using Graph API
        $renameUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices/$deviceId/setDeviceName"
        $headers = @{
            Authorization = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes("Bearer $AccessToken"))
            Accept = "application/json"
            "Content-Type" = "application/json"
        }
        $body = @{ deviceName = $NewName } | ConvertTo-Json
        
        Write-Verbose "Sending rename request to: $renameUri"
        Invoke-RestMethod -Uri $renameUri -Headers $headers -Method Post -Body $body -ErrorAction Stop
        Write-Output "Successfully renamed device '$OriginalDeviceName' to '$NewName'"
        
        # Reboot device using Graph API (if enabled)
        if ($Script:Config.EnableReboot) {
            $rebootUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices/$deviceId/rebootNow"
            Write-Verbose "Initiating reboot for device: $rebootUri"
            try {
                Invoke-RestMethod -Uri $rebootUri -Headers $headers -Method Post -ErrorAction Stop
                Write-Output "Reboot initiated for device '$NewName'"
            }
            catch {
                Write-Warning "Failed to initiate reboot for device '$NewName': $($_.Exception.Message)"
            }
        } else {
            Write-Output "Reboot skipped (disabled in configuration) for device '$NewName'"
        }
    }
    catch {
        $errorMessage = "Failed to rename device '$OriginalDeviceName': $($_.Exception.Message)"
        Write-Error $errorMessage
        throw
    }
}

function Get-IntuneDeviceId {
    <#
    .SYNOPSIS
        Gets the Intune device ID for a device by name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken
    )

    $uri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices" + "?`$filter=deviceName eq '$DeviceName'"
    $headers = @{
        Authorization = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes("Bearer $AccessToken"))
        Accept = "application/json"
    }
    
    Write-Verbose "Searching for device '$DeviceName' in Intune"
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
    
    if (-not $response.value -or $response.value.Count -eq 0) {
        throw "Device with name '$DeviceName' not found in Intune"
    }
    
    if ($response.value.Count -gt 1) {
        Write-Warning "Multiple devices found with name '$DeviceName'. Using the first one."
    }
    
    $deviceId = $response.value[0].id
    Write-Verbose "Found device ID: $deviceId"
    return $deviceId
}

function Get-AccessTokenWithManagedIdentity {
    <#
    .SYNOPSIS
        Gets an access token using Azure Automation Managed Identity.
    .DESCRIPTION
        Uses the system-assigned managed identity of the Azure Automation Account
        to authenticate to Microsoft Graph API using the latest Az.Accounts cmdlets.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Resource = "https://graph.microsoft.com"
    )

    try {
        Write-Host "=== Managed Identity Authentication ===" -ForegroundColor Green
        Write-Host "Attempting to authenticate using Managed Identity..." -ForegroundColor Yellow
        
        # Import Az.Accounts if not already imported
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        # Connect with managed identity
        $context = Connect-AzAccount -Identity -Force -ErrorAction Stop
        Write-Host "✓ Successfully authenticated as Managed Identity" -ForegroundColor Green
        Write-Host "  Account ID: $($context.Context.Account.Id)" -ForegroundColor Gray
        Write-Host "  Account Type: $($context.Context.Account.Type)" -ForegroundColor Gray
        Write-Host "  Tenant ID: $($context.Context.Tenant.Id)" -ForegroundColor Gray
        
        # Get access token
        $tokenRequest = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop
        
        if (-not $tokenRequest.Token) {
            throw "Failed to obtain access token"
        }
        
        Write-Host "✓ Successfully obtained Graph access token" -ForegroundColor Green
        Write-Host "  Token Length: $($tokenRequest.Token.Length) characters" -ForegroundColor Gray
        Write-Host "  Expires On: $($tokenRequest.ExpiresOn)" -ForegroundColor Gray
        Write-Host "  Resource: $Resource" -ForegroundColor Gray
        
        # Let's also check what permissions the token might have by examining it
        $tokenParts = $tokenRequest.Token.Split('.')
        if ($tokenParts.Length -ge 2) {
            try {
                # Decode the payload (second part) of the JWT token
                $payload = $tokenParts[1]
                # Add padding if needed for base64 decoding
                while ($payload.Length % 4) { $payload += "=" }
                $payloadBytes = [System.Convert]::FromBase64String($payload)
                $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
                $payloadObj = $payloadJson | ConvertFrom-Json
                
                Write-Host "  Token App ID: $($payloadObj.appid)" -ForegroundColor Gray
                Write-Host "  Token Audience: $($payloadObj.aud)" -ForegroundColor Gray
                if ($payloadObj.roles) {
                    Write-Host "  Token Roles: $($payloadObj.roles -join ', ')" -ForegroundColor Gray
                }
            }
            catch {
                Write-Verbose "Could not decode token details: $($_.Exception.Message)"
            }
        }
        
        return $tokenRequest.Token
    }
    catch {
        $errorMessage = "Managed Identity authentication failed: $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $errorMessage
    }
}

function Get-DevicePrimaryUserCountryCode {
    <#
    .SYNOPSIS
        Gets the country code for a device's primary user.
    .DESCRIPTION
        Looks up the device in Intune, finds its primary user, and returns the user's usage location.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken
    )

    Write-Verbose "Getting country code for device '$DeviceName'"
    
    try {
        # Get device information including primary user
        $deviceUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices" + "?`$filter=deviceName eq '$DeviceName'"
        $headers = @{
            Authorization = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes("Bearer $AccessToken"))
            Accept = "application/json"
        }
        
        $deviceResponse = Invoke-RestMethod -Uri $deviceUri -Headers $headers -Method Get -ErrorAction Stop
        
        if (-not $deviceResponse.value -or $deviceResponse.value.Count -eq 0) {
            throw "Device with name '$DeviceName' not found in Intune"
        }
        
        $userId = $deviceResponse.value[0].userId
        if (-not $userId) {
            throw "Primary user not found for device '$DeviceName'"
        }

        Write-Verbose "Found primary user ID: $userId"

        # Get user's usage location
        $userUri = "$($Script:Config.GraphBaseUri)/v1.0/users/$userId" + '?$select=usageLocation'
        $userResponse = Invoke-RestMethod -Uri $userUri -Headers $headers -Method Get -ErrorAction Stop
        
        $countryCode = $userResponse.usageLocation
        if (-not $countryCode) {
            throw "Usage location not set for user '$userId' (primary user of device '$DeviceName')"
        }

        $countryCode = $countryCode.ToUpper()
        Write-Verbose "Found country code '$countryCode' for device '$DeviceName'"
        return $countryCode
    }
    catch {
        Write-Error "Failed to get country code for device '$DeviceName': $($_.Exception.Message)"
        throw
    }
}

#region Main Script Execution

# Set verbose preference based on configuration
if ($Script:Config.VerboseLogging) {
    $VerbosePreference = "Continue"
    Write-Output "Verbose logging enabled"
}

Write-Output "=== AutoPilot Device Rename Process Started ==="
Write-Output "Script Version: 4.0 - Final Azure Automation Runbook"
Write-Output "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

try {
    # Get access token using Managed Identity
    $accessToken = Get-AccessTokenWithManagedIdentity

    # Get devices from Entra ID group
    Write-Output "Getting devices from Entra ID group..."
    $groupUri = "$($Script:Config.GraphBaseUri)/v1.0/groups/$($Script:Config.GroupId)/members"
    
    $headers = @{
        Authorization = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes("Bearer $accessToken"))
        Accept = "application/json"
    }
    
    Write-Output "Making request to get group members..."
    Write-Output "  URI: $groupUri"
    Write-Output "  Authorization header length: $($headers.Authorization.Length) characters"
    
    try {
        $groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "Successfully retrieved group members: $($groupResponse.value.Count)"
    }
    catch {
        Write-Error "Failed to get group members: $($_.Exception.Message)"
        Write-Output "Response details:"
        if ($_.Exception.Response) {
            Write-Output "  Status Code: $($_.Exception.Response.StatusCode)"
            Write-Output "  Status Description: $($_.Exception.Response.StatusDescription)"
        }
        throw
    }

    # Filter and process only device members
    $devices = $groupResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }
    
    if (-not $devices) {
        Write-Warning "No devices found in the specified group."
        return
    }

    Write-Output "Found $($devices.Count) device(s) in the group"
    Write-Output ""

    # Initialize counters
    $deviceCount = 0
    $successCount = 0
    $failureCount = 0
    $skippedCount = 0

    foreach ($device in $devices) {
        $deviceCount++
        
        try {
            # Get device details from Entra ID
            $deviceDetailUri = "$($Script:Config.GraphBaseUri)/v1.0/devices/$($device.id)"
            $deviceDetail = Invoke-RestMethod -Uri $deviceDetailUri -Headers $headers -Method Get -ErrorAction Stop
            $originalDeviceName = $deviceDetail.displayName

            Write-Output "[$deviceCount/$($devices.Count)] Processing device: '$originalDeviceName'"
            
            # Get country code for the device's primary user
            $countryCode = Get-DevicePrimaryUserCountryCode -DeviceName $originalDeviceName -AccessToken $accessToken
            
            # Generate new device name
            $newName = New-DeviceName -OriginalDeviceName $originalDeviceName -CountryCode $countryCode
            
            if ($originalDeviceName -eq $newName) {
                Write-Output "  ✓ Device already has correct name format"
                $skippedCount++
            } else {
                # Rename the device
                Rename-Device -OriginalDeviceName $originalDeviceName -NewName $newName -AccessToken $accessToken
                Write-Output "  ✓ Renamed '$originalDeviceName' → '$newName'"
                $successCount++
            }
        }
        catch {
            $errorMsg = "Failed to process '$originalDeviceName': $($_.Exception.Message)"
            Write-Error $errorMsg
            Write-Output "  ✗ $errorMsg"
            $failureCount++
        }
    }

    # Display summary
    Write-Output ""
    Write-Output "=== PROCESS SUMMARY ==="
    Write-Output "Total devices: $deviceCount"
    Write-Output "Successfully renamed: $successCount"
    Write-Output "Already correct: $skippedCount"
    Write-Output "Failed: $failureCount"
    
    if ($failureCount -eq 0) {
        Write-Output "✅ All devices processed successfully!"
    } else {
        Write-Warning "Some devices failed to process. Check the error messages above."
    }
    
    return @{
        TotalDevices = $deviceCount
        SuccessfulRenames = $successCount
        AlreadyCorrect = $skippedCount
        Failed = $failureCount
        Success = ($failureCount -eq 0)
    }
}
catch {
    $errorMessage = "Script execution failed: $($_.Exception.Message)"
    Write-Error $errorMessage
    
    return @{
        TotalDevices = 0
        SuccessfulRenames = 0
        AlreadyCorrect = 0
        Failed = 1
        Success = $false
        ErrorMessage = $errorMessage
    }
}

#endregion