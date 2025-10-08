<#
.SYNOPSIS
    Simple test to check Azure Automation Variables access.

.DESCRIPTION
    This is a minimal script to test if Azure Automation Variables can be accessed
    in your Azure Automation Account environment.
#>

Write-Output "=== Azure Automation Variables Test ==="
Write-Output "Testing Get-AutomationVariable cmdlet availability..."
Write-Output ""

# Test 1: Check if cmdlet exists
try {
    $cmdlet = Get-Command "Get-AutomationVariable" -ErrorAction SilentlyContinue
    if ($cmdlet) {
        Write-Output "✓ Get-AutomationVariable cmdlet is available"
        Write-Output "  Module: $($cmdlet.Source)"
        Write-Output "  Version: $($cmdlet.Version)"
    } else {
        Write-Output "❌ Get-AutomationVariable cmdlet is NOT available"
        Write-Output "Available cmdlets that contain 'Automation':"
        Get-Command "*Automation*" | Select-Object Name, Source | Format-Table
    }
} catch {
    Write-Output "❌ Error checking cmdlet: $($_.Exception.Message)"
}

Write-Output ""

# Test 2: Try to get automation variables
$variableNames = @(
    "AutoPilot-TenantId",
    "AutoPilot-GroupId", 
    "AutoPilot-DevicePrefix",
    "AutoPilot-MaxNameLength",
    "AutoPilot-EnableReboot",
    "AutoPilot-VerboseLogging"
)

Write-Output "Testing individual automation variables..."
foreach ($varName in $variableNames) {
    try {
        if (Get-Command "Get-AutomationVariable" -ErrorAction SilentlyContinue) {
            $value = Get-AutomationVariable -Name $varName -ErrorAction SilentlyContinue
            if ($value) {
                Write-Output "✓ $varName = $value"
            } else {
                Write-Output "⚠ $varName = (empty or not found)"
            }
        } else {
            Write-Output "❌ Cannot test $varName - cmdlet not available"
        }
    } catch {
        Write-Output "❌ Error getting $varName`: $($_.Exception.Message)"
    }
}

Write-Output ""

# Test 3: Check execution context
Write-Output "=== Execution Context Information ==="
Write-Output "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Output "Execution Policy: $(Get-ExecutionPolicy)"
Write-Output "Current User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Test 4: Check available modules
Write-Output ""
Write-Output "=== Available Modules ==="
$modules = Get-Module -ListAvailable | Where-Object { $_.Name -like "*Automation*" -or $_.Name -like "*Az*" }
$modules | Select-Object Name, Version, Path | Format-Table

Write-Output ""
Write-Output "=== Environment Variables ==="
$env:AUTOMATION_ASSET_ENDPOINT
$env:MSI_ENDPOINT
$env:MSI_SECRET

Write-Output "Test completed."