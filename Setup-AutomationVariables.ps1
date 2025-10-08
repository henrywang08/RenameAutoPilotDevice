<#
.SYNOPSIS
    Sets up Azure Automation Variables for the AutoPilot Device Rename script.

.DESCRIPTION
    This helper script creates all required Azure Automation Variables for the 
    AutoPilot device rename process. Run this script to configure your Automation Account.

.PARAMETER AutomationAccountName
    Name of the Azure Automation Account.

.PARAMETER ResourceGroupName
    Name of the Resource Group containing the Automation Account.

.PARAMETER TenantId
    Your Azure AD Tenant ID.

.PARAMETER GroupId
    Object ID of the Entra ID security group containing devices to rename.

.PARAMETER DeviceNamePrefix
    Prefix for device names (default: CMA).

.PARAMETER MaxDeviceNameLength
    Maximum length for device names (default: 15).

.PARAMETER EnableReboot
    Whether to automatically reboot devices after renaming (default: true).

.PARAMETER VerboseLogging
    Whether to enable verbose logging (default: false).

.EXAMPLE
    .\Setup-AutomationVariables.ps1 -AutomationAccountName "MyAutomationAccount" -ResourceGroupName "MyResourceGroup" -TenantId "12345678-1234-1234-1234-123456789012" -GroupId "87654321-4321-4321-4321-210987654321"

.NOTES
    Requires Az.Automation module and appropriate permissions to manage Automation Account.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,
    
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$GroupId,
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceNamePrefix = "CMA",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxDeviceNameLength = 15,
    
    [Parameter(Mandatory = $false)]
    [bool]$EnableReboot = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$VerboseLogging = $false
)

# Import required modules
try {
    Write-Host "Importing required modules..." -ForegroundColor Yellow
    Import-Module Az.Automation -Force -ErrorAction Stop
    Import-Module Az.Accounts -Force -ErrorAction Stop
    Write-Host "✓ Modules imported successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    Write-Host "Please install Az.Automation and Az.Accounts modules:" -ForegroundColor Red
    Write-Host "Install-Module Az.Automation -Force" -ForegroundColor Yellow
    Write-Host "Install-Module Az.Accounts -Force" -ForegroundColor Yellow
    throw
}

# Verify authentication
try {
    Write-Host "Checking Azure authentication..." -ForegroundColor Yellow
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Please authenticate to Azure first:" -ForegroundColor Red
        Write-Host "Connect-AzAccount" -ForegroundColor Yellow
        throw "No Azure authentication context found"
    }
    Write-Host "✓ Authenticated as: $($context.Account.Id)" -ForegroundColor Green
}
catch {
    Write-Error "Azure authentication failed: $($_.Exception.Message)"
    throw
}

# Define automation variables to create
$variables = @(
    @{
        Name = "AutoPilot-TenantId"
        Value = $TenantId
        Description = "Azure AD Tenant ID"
        Encrypted = $false
    },
    @{
        Name = "AutoPilot-GroupId"
        Value = $GroupId
        Description = "Entra ID Group Object ID containing devices to rename"
        Encrypted = $false
    },
    @{
        Name = "AutoPilot-DevicePrefix"
        Value = $DeviceNamePrefix
        Description = "Prefix for device names"
        Encrypted = $false
    },
    @{
        Name = "AutoPilot-MaxNameLength"
        Value = $MaxDeviceNameLength.ToString()
        Description = "Maximum length for device names"
        Encrypted = $false
    },
    @{
        Name = "AutoPilot-EnableReboot"
        Value = $EnableReboot.ToString().ToLower()
        Description = "Whether to automatically reboot devices after renaming"
        Encrypted = $false
    },
    @{
        Name = "AutoPilot-VerboseLogging"
        Value = $VerboseLogging.ToString().ToLower()
        Description = "Whether to enable verbose logging"
        Encrypted = $false
    }
)

Write-Host ""
Write-Host "=== Creating Azure Automation Variables ===" -ForegroundColor Cyan
Write-Host "Automation Account: $AutomationAccountName" -ForegroundColor White
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host ""

$successCount = 0
$errorCount = 0

foreach ($variable in $variables) {
    try {
        Write-Host "Creating variable: $($variable.Name)" -ForegroundColor Yellow
        
        # Check if variable already exists
        $existingVariable = Get-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $variable.Name -ErrorAction SilentlyContinue
        
        if ($existingVariable) {
            Write-Host "  Variable already exists - updating value..." -ForegroundColor Blue
            Set-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $variable.Name -Value $variable.Value -Encrypted $variable.Encrypted -ErrorAction Stop
            Write-Host "  ✓ Updated: $($variable.Name) = $($variable.Value)" -ForegroundColor Green
        } else {
            New-AzAutomationVariable -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $variable.Name -Value $variable.Value -Description $variable.Description -Encrypted $variable.Encrypted -ErrorAction Stop
            Write-Host "  ✓ Created: $($variable.Name) = $($variable.Value)" -ForegroundColor Green
        }
        
        $successCount++
    }
    catch {
        Write-Host "  ❌ Failed to create/update $($variable.Name): $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Successfully created/updated: $successCount variables" -ForegroundColor Green
Write-Host "Failed: $errorCount variables" -ForegroundColor $(if($errorCount -gt 0){"Red"}else{"Green"})

if ($errorCount -eq 0) {
    Write-Host ""
    Write-Host "🎉 All automation variables created successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Upload the Rename-AutoPilotDevice_Azure.ps1 script to your Automation Account" -ForegroundColor White
    Write-Host "2. Create a new runbook using the script" -ForegroundColor White
    Write-Host "3. Test the runbook execution" -ForegroundColor White
    Write-Host "4. Schedule the runbook if needed" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "⚠ Some variables failed to create. Please check the errors above and retry." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "To view all AutoPilot variables in your Automation Account:" -ForegroundColor Cyan
Write-Host "Get-AzAutomationVariable -AutomationAccountName '$AutomationAccountName' -ResourceGroupName '$ResourceGroupName' | Where-Object Name -like 'AutoPilot-*'" -ForegroundColor White