<#
.SYNOPSIS
    Renames AutoPilot devices - Local execution version with Azure Automation Variables support.

.DESCRIPTION
    This script runs locally but can access Azure Automation Variables using the Az.Automation module.
    It supports both parameters and Azure Automation Variables for configuration.

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will try Azure Automation Variable.

.PARAMETER GroupId
    Object ID of the Entra ID group. If not provided, will try Azure Automation Variable.

.PARAMETER AutomationAccountName
    Name of the Azure Automation Account containing the variables.

.PARAMETER ResourceGroupName
    Name of the Resource Group containing the Azure Automation Account.

.NOTES
    Author: AutoPilot Management Team
    Version: 3.3 - Local Execution with Azure Automation Variables Support
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$GroupId,
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceNamePrefix,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxDeviceNameLength,
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableReboot,
    
    [Parameter(Mandatory = $false)]
    [bool]$VerboseLogging,
    
    [Parameter(Mandatory = $false)]
    [string]$AutomationAccountName = "sgAutomationAccount",
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "sgAutomation"
)

# Load required assemblies
Add-Type -AssemblyName System.Web

# Import required modules
try {
    Write-Output "Importing Azure PowerShell modules..."
    Import-Module Az.Accounts -Force
    Import-Module Az.Automation -Force
    Write-Output "Successfully imported required modules"
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    throw
}

# Helper function to get configuration from Azure Automation Variables
function Get-AutomationVariableLocal {
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
        $variable = Get-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $Name -ErrorAction SilentlyContinue
        if ($variable -and $variable.Value) {
            Write-Verbose "Retrieved automation variable '$Name': $($variable.Value)"
            return $variable.Value
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
        $errorMessage = "❌ Required configuration '$Name' not found in automation variables and no default provided"
        Write-Error $errorMessage
        throw $errorMessage
    }
    
    return $null
}

# Load configuration
Write-Output "=== Loading Configuration ==="
Write-Output "Using Azure Automation Variables from account: $AutomationAccountName"
Write-Output ""

try {
    $Script:Config = @{
        TenantId = if ($TenantId) { $TenantId } else { Get-AutomationVariableLocal -Name "AutoPilot-TenantId" -Required }
        GroupId = if ($GroupId) { $GroupId } else { Get-AutomationVariableLocal -Name "AutoPilot-GroupId" -Required }
        DeviceNamePrefix = if ($DeviceNamePrefix) { $DeviceNamePrefix } else { Get-AutomationVariableLocal -Name "AutoPilot-DevicePrefix" -DefaultValue "CMA" }
        MaxDeviceNameLength = if ($MaxDeviceNameLength -gt 0) { $MaxDeviceNameLength } else { [int]([string](Get-AutomationVariableLocal -Name "AutoPilot-MaxNameLength" -DefaultValue "15")) }
        EnableReboot = if ($PSBoundParameters.ContainsKey('EnableReboot')) { $EnableReboot } else { [System.Convert]::ToBoolean([string](Get-AutomationVariableLocal -Name "AutoPilot-EnableReboot" -DefaultValue "true")) }
        VerboseLogging = if ($PSBoundParameters.ContainsKey('VerboseLogging')) { $VerboseLogging } else { [System.Convert]::ToBoolean([string](Get-AutomationVariableLocal -Name "AutoPilot-VerboseLogging" -DefaultValue "false")) }
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

function Get-AccessTokenWithServicePrincipal {
    <#
    .SYNOPSIS
        Gets an access token using interactive authentication for local testing.
    .DESCRIPTION
        Since this is running locally, we'll use interactive authentication
        to get an access token for Microsoft Graph API.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Resource = "https://graph.microsoft.com"
    )

    try {
        Write-Output "=== Authentication ==="
        Write-Output "Attempting to authenticate to Microsoft Graph..."
        
        # Connect to Azure with the specified tenant
        $context = Connect-AzAccount -TenantId $Script:Config.TenantId -Force -ErrorAction Stop
        Write-Output "✓ Successfully authenticated to Azure"
        Write-Output "  Account: $($context.Context.Account.Id)"
        Write-Output "  Tenant: $($context.Context.Tenant.Id)"
        
        # Get access token for Microsoft Graph
        $tokenRequest = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop
        
        if (-not $tokenRequest.Token) {
            throw "Failed to obtain access token"
        }
        
        Write-Output "✓ Successfully obtained Graph access token"
        Write-Output "  Token Length: $($tokenRequest.Token.Length) characters"
        Write-Output "  Expires On: $($tokenRequest.ExpiresOn)"
        
        return $tokenRequest.Token
    }
    catch {
        $errorMessage = "Authentication failed: $($_.Exception.Message)"
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
Write-Output "Script Version: 3.3 - Local Execution with Azure Automation Variables Support"
Write-Output "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

try {
    # Get access token using interactive authentication
    $accessToken = Get-AccessTokenWithServicePrincipal

    # Get devices from Entra ID group
    Write-Output "Getting devices from Entra ID group..."
    $groupUri = "$($Script:Config.GraphBaseUri)/v1.0/groups/$($Script:Config.GroupId)/members"
    
    $headers = @{
        Authorization = [System.Text.Encoding]::ASCII.GetString([System.Text.Encoding]::ASCII.GetBytes("Bearer $accessToken"))
        Accept = "application/json"
    }
    
    Write-Output "Making request to get group members..."
    $groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get -ErrorAction Stop
    Write-Output "Successfully retrieved group members: $($groupResponse.value.Count)"

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