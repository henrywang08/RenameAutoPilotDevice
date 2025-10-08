<#
.SYNOPSIS
    Renames AutoPilot devices - Hybrid version supporting both parameters and Azure Automation Variables.

.DESCRIPTION
    This script can run both locally with parameters and in Azure Automation with variables.
    When run in Azure Automation, it prioritizes Automation Variables but falls back to parameters if variables are not set.

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will try to get from Automation Variable 'AutoPilot-TenantId'

.PARAMETER GroupId
    Object ID of the Entra ID group containing devices to rename. If not provided, will try to get from Automation Variable 'AutoPilot-GroupId'

.PARAMETER DeviceNamePrefix
    Prefix for device names. If not provided, will try to get from Automation Variable 'AutoPilot-DevicePrefix' or default to 'CMA'

.PARAMETER MaxDeviceNameLength
    Maximum length for device names. If not provided, will try to get from Automation Variable 'AutoPilot-MaxNameLength' or default to 15

.PARAMETER EnableReboot
    Whether to automatically reboot devices after renaming. If not provided, will try to get from Automation Variable 'AutoPilot-EnableReboot' or default to true

.PARAMETER VerboseLogging
    Whether to enable verbose logging. If not provided, will try to get from Automation Variable 'AutoPilot-VerboseLogging' or default to false

.EXAMPLE
    # Run with parameters (works locally or in Azure Automation)
    .\Rename-AutoPilotDevice_Hybrid.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -GroupId "87654321-4321-4321-4321-210987654321"

.EXAMPLE
    # Run using Azure Automation Variables (recommended for Azure Automation)
    .\Rename-AutoPilotDevice_Hybrid.ps1

.NOTES
    Author: AutoPilot Management Team
    Version: 3.1 - Hybrid Parameter/Variable Support
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
    [bool]$VerboseLogging
)

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

# Helper function to get configuration value (parameter, then automation variable, then default)
function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        $ParameterValue = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$AutomationVariableName,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = $null,
        
        [Parameter(Mandatory = $false)]
        [switch]$Required
    )
    
    # First, check if parameter was provided
    if ($ParameterValue -and $ParameterValue -ne "") {
        Write-Output "✓ Using parameter value for '$Name': $ParameterValue"
        return $ParameterValue
    }
    
    # Second, try automation variable if we're in Azure Automation
    if ($AutomationVariableName) {
        try {
            if (Get-Command "Get-AutomationVariable" -ErrorAction SilentlyContinue) {
                $value = Get-AutomationVariable -Name $AutomationVariableName -ErrorAction SilentlyContinue
                if ($value) {
                    Write-Output "✓ Using automation variable '$AutomationVariableName' for '$Name': $value"
                    return $value
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve automation variable '$AutomationVariableName': $($_.Exception.Message)"
        }
    }
    
    # Third, use default value
    if ($DefaultValue) {
        Write-Output "⚠ Using default value for '$Name': $DefaultValue"
        return $DefaultValue
    }
    
    # If required and no value found, throw error
    if ($Required) {
        $errorMessage = @"
❌ Required configuration '$Name' not provided

Provide the value using one of these methods:
1. Script Parameter: -$Name "your-value"
2. Azure Automation Variable: $AutomationVariableName
3. Default value (if available)

Current status:
- Parameter '$Name': $(if($ParameterValue){"Provided"}else{"Not provided"})
- Automation Variable '$AutomationVariableName': $(if($AutomationVariableName){"Not found or empty"}else{"Not checked"})
- Default Value: $(if($DefaultValue){"Available: $DefaultValue"}else{"None"})
"@
        Write-Error $errorMessage
        throw $errorMessage
    }
    
    return $null
}

# Load configuration using hybrid approach
Write-Output "=== Loading Configuration (Hybrid Mode: Parameters + Azure Automation Variables) ==="

try {
    $Script:Config = @{
        TenantId = Get-ConfigValue -Name "TenantId" -ParameterValue $TenantId -AutomationVariableName "AutoPilot-TenantId" -Required
        GroupId = Get-ConfigValue -Name "GroupId" -ParameterValue $GroupId -AutomationVariableName "AutoPilot-GroupId" -Required
        DeviceNamePrefix = Get-ConfigValue -Name "DeviceNamePrefix" -ParameterValue $DeviceNamePrefix -AutomationVariableName "AutoPilot-DevicePrefix" -DefaultValue "CMA"
        MaxDeviceNameLength = [int](Get-ConfigValue -Name "MaxDeviceNameLength" -ParameterValue $MaxDeviceNameLength -AutomationVariableName "AutoPilot-MaxNameLength" -DefaultValue "15")
        EnableReboot = if ($PSBoundParameters.ContainsKey('EnableReboot')) { 
            $EnableReboot 
        } else { 
            $automationRebootValue = Get-ConfigValue -Name "EnableReboot" -AutomationVariableName "AutoPilot-EnableReboot" -DefaultValue "true"
            [System.Convert]::ToBoolean($automationRebootValue)
        }
        VerboseLogging = if ($PSBoundParameters.ContainsKey('VerboseLogging')) { 
            $VerboseLogging 
        } else { 
            $automationVerboseValue = Get-ConfigValue -Name "VerboseLogging" -AutomationVariableName "AutoPilot-VerboseLogging" -DefaultValue "false"
            [System.Convert]::ToBoolean($automationVerboseValue)
        }
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
}
catch {
    Write-Error "Configuration failed: $($_.Exception.Message)"
    Write-Output ""
    Write-Output "QUICK SETUP for Azure Automation:"
    Write-Output "Run this command to create all required variables:"
    Write-Output ""
    Write-Output ".\Setup-AutomationVariables.ps1 -AutomationAccountName 'YourAutomationAccount' -ResourceGroupName 'YourResourceGroup' -TenantId 'your-tenant-id' -GroupId 'your-group-id'"
    Write-Output ""
    Write-Output "OR run with parameters directly:"
    Write-Output ""
    Write-Output ".\Rename-AutoPilotDevice_Hybrid.ps1 -TenantId 'your-tenant-id' -GroupId 'your-group-id'"
    throw
}

# Include all the same functions from the main script (condensed for brevity)
# ... [All the same functions: New-DeviceName, Rename-Device, Get-IntuneDeviceId, Get-AccessTokenWithManagedIdentity, Get-DevicePrimaryUserCountryCode] ...

Write-Output "=== AutoPilot Device Rename Process Started (Hybrid Mode) ==="
Write-Output "Script Version: 3.1 - Hybrid Parameter/Variable Support"
Write-Output "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

# Continue with the same main execution logic as the original script...
# This is a template - you would include all the same functions and main execution logic from the original script