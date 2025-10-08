#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Tests Azure Automation Variables accessibility.

.DESCRIPTION
    This diagnostic script verifies that Azure Automation Variables can be accessed
    from within the Azure Automation runbook environment.
#>

Write-Output "=== Azure Automation Variables Diagnostic ==="
Write-Output "Test Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

# Check environment
Write-Output "Environment Check:"
Write-Output "  AUTOMATION_ASSET_ENDPOINT: $env:AUTOMATION_ASSET_ENDPOINT"
Write-Output "  MSI_ENDPOINT: $env:MSI_ENDPOINT"
Write-Output "  MSI_SECRET: $(if($env:MSI_SECRET){'[SET]'}else{'[NOT SET]'})"
Write-Output ""

# Check if Get-AutomationVariable cmdlet is available
Write-Output "Cmdlet Availability:"
$getAutoVarCmd = Get-Command "Get-AutomationVariable" -ErrorAction SilentlyContinue
if ($getAutoVarCmd) {
    Write-Output "✓ Get-AutomationVariable cmdlet is available"
    Write-Output "  Module: $($getAutoVarCmd.ModuleName)"
    Write-Output "  Source: $($getAutoVarCmd.Source)"
} else {
    Write-Output "❌ Get-AutomationVariable cmdlet is NOT available"
    Write-Output ""
    Write-Output "Available Automation cmdlets:"
    Get-Command "*Automation*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "  - $($_.Name)"
    }
}
Write-Output ""

# Test accessing specific variables
$variablesToTest = @(
    "AutoPilot-TenantId",
    "AutoPilot-GroupId", 
    "AutoPilot-DevicePrefix",
    "AutoPilot-MaxNameLength",
    "AutoPilot-EnableReboot",
    "AutoPilot-VerboseLogging"
)

Write-Output "Testing Individual Variables:"
foreach ($varName in $variablesToTest) {
    Write-Output "Testing variable: $varName"
    
    try {
        if ($getAutoVarCmd) {
            $value = Get-AutomationVariable -Name $varName -ErrorAction Stop
            if ($value) {
                Write-Output "  ✓ SUCCESS: $varName = $value"
            } else {
                Write-Output "  ⚠ EMPTY: $varName exists but has no value"
            }
        } else {
            Write-Output "  ❌ SKIP: Get-AutomationVariable not available"
        }
    }
    catch {
        Write-Output "  ❌ ERROR: $($_.Exception.Message)"
    }
}

Write-Output ""
Write-Output "Alternative Methods:"

# Try alternative ways to access automation variables
Write-Output ""
Write-Output "Method 1: Direct Get-AutomationVariable with error handling"
try {
    $testValue = Get-AutomationVariable -Name "AutoPilot-TenantId" -ErrorAction SilentlyContinue
    if ($testValue) {
        Write-Output "✓ Direct method works: $testValue"
    } else {
        Write-Output "⚠ Direct method returns empty/null"
    }
}
catch {
    Write-Output "❌ Direct method failed: $($_.Exception.Message)"
}

Write-Output ""
Write-Output "Method 2: Try with different error action"
try {
    $testValue2 = Get-AutomationVariable -Name "AutoPilot-TenantId" -ErrorAction Continue
    Write-Output "✓ Continue method result: $testValue2"
}
catch {
    Write-Output "❌ Continue method failed: $($_.Exception.Message)"
}

Write-Output ""
Write-Output "Method 3: List all available variables"
try {
    $allVars = Get-AutomationVariable -ErrorAction SilentlyContinue
    if ($allVars) {
        Write-Output "✓ Found $($allVars.Count) total automation variables:"
        $allVars | Where-Object { $_.Name -like "*AutoPilot*" } | ForEach-Object {
            Write-Output "  - $($_.Name) = $($_.Value)"
        }
    } else {
        Write-Output "⚠ No automation variables found or cmdlet failed"
    }
}
catch {
    Write-Output "❌ List all variables failed: $($_.Exception.Message)"
}

Write-Output ""
Write-Output "=== Diagnostic Summary ==="
if ($getAutoVarCmd) {
    Write-Output "✓ Get-AutomationVariable cmdlet is available"
    Write-Output "This suggests the issue may be with:"
    Write-Output "  1. Variable names (case sensitivity)"
    Write-Output "  2. Variable values (empty/null)"
    Write-Output "  3. Permissions to access variables"
    Write-Output "  4. Timing issues (variables not yet available)"
} else {
    Write-Output "❌ Get-AutomationVariable cmdlet is NOT available"
    Write-Output "This suggests:"
    Write-Output "  1. Not running in Azure Automation environment"
    Write-Output "  2. Missing PowerShell module"
    Write-Output "  3. Different Azure Automation version"
}

Write-Output ""
Write-Output "Recommended Actions:"
Write-Output "1. Verify you're running this in Azure Automation Account runbook"
Write-Output "2. Check variable names are exact matches (case sensitive)"
Write-Output "3. Verify variables were created successfully in Azure portal"
Write-Output "4. Try running the Setup-AutomationVariables.ps1 script again"