<#
.SYNOPSIS
    Renames AutoPilot devices based on primary user's country location - Azure Automation Version.

.DESCRIPTION
    This script is designed to run in Azure Automation Account using Managed Identity authentication.
    It retrieves devices from a specified Entra ID group, determines each device's primary
    user's country, and renames the device with a country-specific prefix.
    
    All configuration is managed through Azure Automation Variables for easy management.

.NOTES
    Author: AutoPilot Management Team
    Version: 3.0 - Azure Automation Variables Compatible
    
    Prerequisites for Azure Automation Account:
    1. System-assigned Managed Identity enabled
    2. Managed Identity granted the following Graph API permissions:
       - DeviceManagementManagedDevices.Read.All
       - DeviceManagementManagedDevices.PrivilegedOperations.All
       - Device.ReadWrite.All
       - Group.Read.All
       - GroupMember.Read.All
       - User.Read.All
    3. Required Automation Variables:
       - AutoPilot-TenantId: Your Azure AD Tenant ID
       - AutoPilot-GroupId: Entra ID Group Object ID containing devices to rename
       - AutoPilot-DevicePrefix: Device name prefix (default: CMA)
       - AutoPilot-MaxNameLength: Maximum device name length (default: 15)
    4. Required PowerShell modules imported in Automation Account:
       - Az.Accounts

.EXAMPLE
    # This script runs without parameters using Azure Automation Variables
    .\Rename-AutoPilotDevice_Azure.ps1
    
    Prerequisites for Azure Automation Account:
    1. System-assigned Managed Identity enabled
    2. Managed Identity granted the following Graph API permissions:
       - DeviceManagementManagedDevices.Read.All
       - DeviceManagementManagedDevices.PrivilegedOperations.All
       - Device.ReadWrite.All
       - Group.Read.All
       - GroupMember.Read.All
       - User.Read.All
    3. Required Automation Variables (optional):
       - AutoPilot-TenantId: Your Azure AD Tenant ID
       - AutoPilot-GroupId: Entra ID Group Object ID
       - AutoPilot-DevicePrefix: Device name prefix (default: CMA)
       - AutoPilot-MaxNameLength: Maximum device name length (default: 15)
    4. Required PowerShell modules imported in Automation Account:
       - Az.Accounts (contains all necessary cmdlets for Managed Identity authentication)

.SETUP_GUIDE
    AZURE AUTOMATION SETUP STEPS:
    
    1. CREATE AUTOMATION ACCOUNT:
       - Go to Azure Portal > Create Resource > Automation Account
       - Choose subscription, resource group, name, and region
       - Enable System-assigned Managed Identity during creation
    
    2. CONFIGURE MANAGED IDENTITY PERMISSIONS:
       - Go to Azure Portal > Entra ID > App registrations
       - Search for your Automation Account name (it will appear as an Enterprise Application)
       - Note the Object ID of the Managed Identity
       - Go to Entra ID > App registrations > Microsoft Graph
       - Click "API permissions" > "Add a permission" > "Microsoft Graph" > "Application permissions"
       - Add these permissions for your Automation Account's Managed Identity:
         * DeviceManagementManagedDevices.Read.All
         * DeviceManagementManagedDevices.PrivilegedOperations.All
         * Device.ReadWrite.All
         * Group.Read.All
         * GroupMember.Read.All
         * User.Read.All
       - Click "Grant admin consent"
    
    3. IMPORT REQUIRED MODULES:
       - Go to Automation Account > Modules > Browse Gallery
       - Search and import: Az.Accounts (this now includes all necessary authentication features)
       - Wait for import to complete (check Modules tab)
    
    4. SET UP AUTOMATION VARIABLES (Required):
       - Go to Automation Account > Variables
       - Create these variables:
         * Name: AutoPilot-TenantId, Value: Your Azure AD Tenant ID
         * Name: AutoPilot-GroupId, Value: Your Entra ID Group Object ID
         * Name: AutoPilot-DevicePrefix, Value: CMA (or your preferred prefix)
         * Name: AutoPilot-MaxNameLength, Value: 15 (or your preferred max length)
         * Name: AutoPilot-EnableReboot, Value: true (set to false to disable automatic reboot)
         * Name: AutoPilot-VerboseLogging, Value: false (set to true for detailed logging)
    
    5. CREATE RUNBOOK:
       - Go to Automation Account > Runbooks > Create a runbook
       - Name: Rename-AutoPilot-Devices
       - Type: PowerShell
       - Paste this script content
       - Save and Publish
    
    6. SCHEDULE RUNBOOK (Optional):
       - Go to Runbooks > Your Runbook > Schedules
       - Create a new schedule (e.g., daily, weekly)
       - Link the schedule to your runbook
    
    7. TEST THE RUNBOOK:
       - Go to Runbooks > Your Runbook > Start
       - Monitor execution in "Jobs" tab
       - Check output and any errors

.LINK
    https://docs.microsoft.com/en-us/azure/automation/
#>

# This script uses Azure Automation Variables for all configuration
# No parameters needed - all settings managed through Automation Variables

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
    Write-Error "Please ensure Az.Accounts module is installed in the Automation Account"
    throw
}

# Helper function to get Automation Variables
function Get-AutomationVariable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = $null,
        
        [Parameter(Mandatory = $false)]
        [switch]$Required
    )
    
    try {
        # Check if Get-AutomationVariable cmdlet is available
        if (Get-Command "Get-AutomationVariable" -ErrorAction SilentlyContinue) {
            # Try to get the automation variable
            $value = Get-AutomationVariable -Name $Name -ErrorAction SilentlyContinue
            if ($value) {
                Write-Output "✓ Retrieved automation variable '$Name': $value"
                return $value
            } else {
                Write-Verbose "Automation variable '$Name' exists but has no value or is empty"
            }
        } else {
            Write-Warning "Get-AutomationVariable cmdlet not available - may not be running in Azure Automation or cmdlet not imported"
        }
    }
    catch {
        Write-Verbose "Error accessing automation variable '$Name': $($_.Exception.Message)"
    }
    
    # If automation variable not found, use default
    if ($DefaultValue) {
        Write-Output "⚠ Using default value for '$Name': $DefaultValue"
        return $DefaultValue
    }
    
    # If required and no default, provide helpful error message
    if ($Required) {
        $errorMessage = @"
❌ Required automation variable '$Name' not found and no default value provided

SOLUTION: Create the automation variable using one of these methods:

Method 1 - Use the Setup Script (Recommended):
Run: .\Setup-AutomationVariables.ps1 -AutomationAccountName "YourAutomationAccount" -ResourceGroupName "YourResourceGroup" -TenantId "your-tenant-id" -GroupId "your-group-id"

Method 2 - Manual Setup in Azure Portal:
1. Go to Azure Portal > Your Automation Account > Variables
2. Create variable: Name=$Name, Type=String, Value=<your-value>

Method 3 - PowerShell Command:
New-AzAutomationVariable -AutomationAccountName "YourAccount" -ResourceGroupName "YourRG" -Name "$Name" -Value "your-value"

Required Variables:
- AutoPilot-TenantId: Your Azure AD Tenant ID
- AutoPilot-GroupId: Entra ID Group Object ID containing devices to rename
- AutoPilot-DevicePrefix: Device name prefix (optional, default: CMA)
- AutoPilot-MaxNameLength: Maximum device name length (optional, default: 15)
- AutoPilot-EnableReboot: Enable automatic reboot (optional, default: true)
- AutoPilot-VerboseLogging: Enable detailed logging (optional, default: false)
"@
        Write-Error $errorMessage
        throw $errorMessage
    }
    
    return $null
}

# Load configuration from Azure Automation Variables
Write-Output "=== Loading Configuration from Azure Automation Variables ==="

$Script:Config = @{
    TenantId = Get-AutomationVariable -Name "AutoPilot-TenantId" -Required
    GroupId = Get-AutomationVariable -Name "AutoPilot-GroupId" -Required
    DeviceNamePrefix = Get-AutomationVariable -Name "AutoPilot-DevicePrefix" -DefaultValue "CMA"
    MaxDeviceNameLength = [int](Get-AutomationVariable -Name "AutoPilot-MaxNameLength" -DefaultValue "15")
    EnableReboot = [System.Convert]::ToBoolean((Get-AutomationVariable -Name "AutoPilot-EnableReboot" -DefaultValue "true"))
    VerboseLogging = [System.Convert]::ToBoolean((Get-AutomationVariable -Name "AutoPilot-VerboseLogging" -DefaultValue "false"))
    GraphBaseUri = "https://graph.microsoft.com"
}

Write-Output "Configuration loaded successfully:"
Write-Output "  Tenant ID: $($Script:Config.TenantId)"
Write-Output "  Group ID: $($Script:Config.GroupId)"
Write-Output "  Device Prefix: $($Script:Config.DeviceNamePrefix)"
Write-Output "  Max Name Length: $($Script:Config.MaxDeviceNameLength)"
Write-Output "  Enable Reboot: $($Script:Config.EnableReboot)"
Write-Output "  Verbose Logging: $($Script:Config.VerboseLogging)"
Write-Output ""

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
    $expectedPrefix = "$($Script:Config.DeviceNamePrefix)$CountryCode-"
    if ($OriginalDeviceName -match "^$expectedPrefix") {
        Write-Verbose "Device '$OriginalDeviceName' already has correct country prefix"
        return $OriginalDeviceName
    }

    # Extract the suffix from original name (everything after the first 3 characters)
    if ($OriginalDeviceName.Length -gt 3) {
        $suffix = $OriginalDeviceName.Substring(3)
    } else {
        $suffix = $OriginalDeviceName
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
            Authorization = "Bearer $AccessToken"
            Accept        = "application/json"
            "Content-Type" = "application/json"
        }
        $body = @{ deviceName = $NewName } | ConvertTo-Json
        
        Write-Verbose "Sending rename request to: $renameUri"
        $response = Invoke-RestMethod -Uri $renameUri -Headers $headers -Method Post -Body $body -ErrorAction Stop
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
                # Don't fail the entire operation if reboot fails
            }
        } else {
            Write-Output "Reboot skipped (disabled in configuration) for device '$NewName'"
        }
    }
    catch {
        $errorMessage = "Failed to rename device '$OriginalDeviceName': $($_.Exception.Message)"
        
        # Enhanced error handling for HTTP responses
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $statusDesc = $_.Exception.Response.ReasonPhrase
            $errorMessage += " (HTTP $statusCode $statusDesc)"
            
            # Try to get response body for more details
            try {
                if ($_.Exception.Response.Content) {
                    $responseBody = $_.Exception.Response.Content.ReadAsStringAsync().Result
                    if ($responseBody) {
                        $errorMessage += " - Response: $responseBody"
                    }
                }
            }
            catch {
                # Ignore errors reading response body
            }
        }
        
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
        Authorization = "Bearer $AccessToken"
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
        Write-Output "=== Managed Identity Authentication Debug ==="
        Write-Output "Attempting to authenticate using Managed Identity..."
        Write-Output "Target Resource: $Resource"
        
        # Check if we're running in Azure Automation
        if ($env:AUTOMATION_ASSET_ENDPOINT) {
            Write-Output "Running in Azure Automation Account: $env:AUTOMATION_ASSET_ENDPOINT"
        } else {
            Write-Output "WARNING: AUTOMATION_ASSET_ENDPOINT not found - may not be running in Azure Automation"
        }
        
        # Check for MSI_ENDPOINT which is used by Managed Identity in Azure Automation
        if ($env:MSI_ENDPOINT) {
            Write-Output "MSI Endpoint detected: $env:MSI_ENDPOINT"
        } else {
            Write-Output "WARNING: MSI_ENDPOINT not found"
        }
        
        # Import Az.Accounts if not already imported
        Write-Output "Ensuring Az.Accounts module is loaded..."
        Import-Module Az.Accounts -Force -ErrorAction Stop
        
        # Try multiple authentication methods for Azure Automation
        Write-Output "Attempting Managed Identity authentication..."
        
        # Method 1: Try Connect-AzAccount with Identity switch
        try {
            Write-Output "Method 1: Connect-AzAccount -Identity"
            $context = Connect-AzAccount -Identity -Force -ErrorAction Stop
            Write-Output "✓ Successfully authenticated as Managed Identity"
            Write-Output "  Account ID: $($context.Context.Account.Id)"
            Write-Output "  Account Type: $($context.Context.Account.Type)"
            Write-Output "  Tenant ID: $($context.Context.Tenant.Id)"
            
            # Get access token for Microsoft Graph
            Write-Output "Requesting access token for Microsoft Graph..."
            
            # Try different token request methods
            $tokenRequest = $null
            
            # Try ResourceUrl parameter (newer method)
            try {
                Write-Output "Trying Get-AzAccessToken with -ResourceUrl parameter..."
                $tokenRequest = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop
            }
            catch {
                Write-Output "ResourceUrl method failed: $($_.Exception.Message)"
                
                # Try Resource parameter (older method)
                try {
                    Write-Output "Trying Get-AzAccessToken with -Resource parameter..."
                    $tokenRequest = Get-AzAccessToken -Resource $Resource -ErrorAction Stop
                }
                catch {
                    Write-Output "Resource method failed: $($_.Exception.Message)"
                    throw "Both token request methods failed"
                }
            }
            
            if (-not $tokenRequest.Token) {
                throw "Failed to obtain access token from Get-AzAccessToken"
            }
            
            # Display token information (without exposing the actual token)
            Write-Output "✓ Successfully obtained Graph access token"
            Write-Output "  Token Type: Bearer"
            Write-Output "  Expires On: $($tokenRequest.ExpiresOn)"
            Write-Output "  Token Length: $($tokenRequest.Token.Length) characters"
            
            # Validate token by checking its structure
            if ($tokenRequest.Token -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') {
                Write-Output "  Token structure: Valid JWT format"
            } else {
                Write-Output "  WARNING: Token does not appear to be in JWT format"
            }
            
            Write-Output "=== Authentication Completed Successfully ==="
            return $tokenRequest.Token
        }
        catch {
            Write-Output "Method 1 failed: $($_.Exception.Message)"
            
            # Method 2: Try direct REST API call to MSI endpoint (fallback for older Azure Automation)
            if ($env:MSI_ENDPOINT) {
                Write-Output "Method 2: Direct MSI endpoint call"
                
                try {
                    $msiEndpoint = $env:MSI_ENDPOINT
                    $msiSecret = $env:MSI_SECRET
                    
                    if (-not $msiSecret) {
                        throw "MSI_SECRET environment variable not found"
                    }
                    
                    $tokenUri = "$msiEndpoint/?resource=$([System.Web.HttpUtility]::UrlEncode($Resource))&api-version=2017-09-01"
                    $headers = @{ 'Secret' = $msiSecret }
                    
                    Write-Output "Making direct MSI token request..."
                    Write-Output "Token URI: $tokenUri"
                    
                    $response = Invoke-RestMethod -Uri $tokenUri -Headers $headers -Method Get -ErrorAction Stop
                    
                    if ($response.access_token) {
                        Write-Output "✓ Successfully obtained token via direct MSI endpoint"
                        Write-Output "  Token Type: $($response.token_type)"
                        Write-Output "  Expires In: $($response.expires_in) seconds"
                        Write-Output "  Token Length: $($response.access_token.Length) characters"
                        
                        Write-Output "=== Authentication Completed Successfully (MSI Direct) ==="
                        return $response.access_token
                    } else {
                        throw "No access token in MSI response"
                    }
                }
                catch {
                    Write-Output "Method 2 failed: $($_.Exception.Message)"
                    throw "All authentication methods failed"
                }
            } else {
                throw "No MSI endpoint available for fallback authentication"
            }
        }
    }
    catch {
        $errorMessage = "Managed Identity authentication failed: $($_.Exception.Message)"
        Write-Error $errorMessage
        Write-Output "Full error details: $($_.Exception.ToString())"
        
        # Enhanced error information for troubleshooting
        Write-Output "=== Troubleshooting Information ==="
        Write-Output "Environment Variables:"
        Write-Output "  AUTOMATION_ASSET_ENDPOINT: $env:AUTOMATION_ASSET_ENDPOINT"
        Write-Output "  MSI_ENDPOINT: $env:MSI_ENDPOINT"
        Write-Output "  MSI_SECRET: $(if($env:MSI_SECRET){'[SET]'}else{'[NOT SET]'})"
        Write-Output ""
        Write-Output "Possible Issues:"
        Write-Output "- Ensure the Automation Account has System-assigned Managed Identity enabled"
        Write-Output "- Verify the Managed Identity has the required Graph API permissions"
        Write-Output "- Check that Az.Accounts module is properly imported"
        Write-Output "- Confirm the Managed Identity object ID matches what was granted permissions"
        Write-Output "- Wait 5-10 minutes after enabling Managed Identity or granting permissions"
        Write-Output "=== End Troubleshooting ==="
        
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
    
    # Set verbose preference based on configuration
    if ($Script:Config.VerboseLogging) {
        $VerbosePreference = "Continue"
    }
    
    try {
        # Get device information including primary user
        $deviceUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices" + "?`$filter=deviceName eq '$DeviceName'"
        $headers = @{
            Authorization = "Bearer $AccessToken"
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
} else {
    $VerbosePreference = "SilentlyContinue"
}

# Validate configuration
Write-Output "=== AutoPilot Device Rename Process Started (Azure Automation) ==="
Write-Output "Script Version: 3.0 - Azure Automation Variables Compatible"
Write-Output "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""
Write-Output "Configuration Summary:"
Write-Output "  Tenant ID: $($Script:Config.TenantId)"
Write-Output "  Group ID: $($Script:Config.GroupId)"
Write-Output "  Device Prefix: $($Script:Config.DeviceNamePrefix)"
Write-Output "  Max Name Length: $($Script:Config.MaxDeviceNameLength)"
Write-Output "  Enable Reboot: $($Script:Config.EnableReboot)"
Write-Output "  Verbose Logging: $($Script:Config.VerboseLogging)"
Write-Output ""

try {
    # Get access token using Managed Identity
    $accessToken = Get-AccessTokenWithManagedIdentity

    # Get devices from Entra ID group
    Write-Output "Getting devices from Entra ID group..."
    $groupUri = "$($Script:Config.GraphBaseUri)/v1.0/groups/$($Script:Config.GroupId)/members"
    
    Write-Output "=== Group Query Debug ==="
    Write-Output "Group URI: $groupUri"
    Write-Output "Group ID: $($Script:Config.GroupId)"
    
    $headers = @{
        Authorization = "Bearer $accessToken"
        Accept = "application/json"
    }
    
    Write-Output "Headers configured: Authorization (Bearer token), Content-Type, Accept"
    Write-Output "Making request to get group members..."
    
    try {
        $groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "Successfully retrieved group members"
        Write-Output "Total members found: $($groupResponse.value.Count)"
    }
    catch {
        Write-Error "Failed to get group members: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            Write-Output "HTTP Status Code: $statusCode"
            
            if ($statusCode -eq 401) {
                Write-Output "=== 401 Error - Possible Causes ==="
                Write-Output "1. Managed Identity authentication failed"
                Write-Output "2. Missing Graph API permissions: Group.Read.All"
                Write-Output "3. Group ID '$($Script:Config.GroupId)' may not exist"
                Write-Output "4. Token may be invalid or expired"
                Write-Output "=== Verifying Token and Permissions ==="
                
                # Instead of testing with /me (which doesn't work for app auth), 
                # try a simple service principal lookup
                Write-Output "Testing token with service principal lookup..."
                try {
                    # Get the object ID from the token for proper SP lookup
                    $tokenParts = $accessToken.Split('.')
                    $payloadBytes = [Convert]::FromBase64String(($tokenParts[1] + "===").Substring(0, ($tokenParts[1].Length + 3) -band -4))
                    $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
                    $objectId = $payload.oid
                    
                    $testUri = "$($Script:Config.GraphBaseUri)/v1.0/servicePrincipals/$objectId"
                    $testHeaders = @{
                        Authorization = "Bearer $accessToken"
                        Accept = "application/json"
                    }
                    $testResponse = Invoke-RestMethod -Uri $testUri -Headers $testHeaders -Method Get -ErrorAction Stop
                    Write-Output "Token is valid - issue is likely with group permissions or group ID"
                    Write-Output "Service Principal: $($testResponse.displayName)"
                }
                catch {
                    Write-Output "Token test failed - authentication issue confirmed"
                    Write-Output "Token test error: $($_.Exception.Message)"
                }
            }
        }
        throw
    }

    # Filter and process only device members
    $devices = $groupResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }
    
    if (-not $devices) {
        Write-Warning "No devices found in the specified group."
        Write-Output "Script completed with no devices to process."
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
        Write-Output "All devices processed successfully!"
    } else {
        Write-Warning "Some devices failed to process. Check the error messages above."
        # In Azure Automation, we don't exit with error codes as it would stop the runbook
        # Instead, we just log the issues
    }
    
    # Return summary object for potential use by calling runbooks
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
    Write-Output $errorMessage
    
    # Return error result
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