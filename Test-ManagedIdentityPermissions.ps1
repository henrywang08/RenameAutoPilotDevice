#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Tests Azure Automation Managed Identity permissions for Microsoft Graph API.

.DESCRIPTION
    This diagnostic script verifies that the Managed Identity has proper access to 
    Microsoft Graph API and can perform the required operations for device renaming.

.NOTES
    Run this in Azure Automation Account to diagnose permission issues.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GroupId
)

# Load required assemblies
Add-Type -AssemblyName System.Web

function Test-ManagedIdentityAuth {
    try {
        Write-Output "=== Testing Managed Identity Authentication ==="
        
        # Check environment
        if ($env:AUTOMATION_ASSET_ENDPOINT) {
            Write-Output "✓ Running in Azure Automation Account"
            Write-Output "  Automation Endpoint: $env:AUTOMATION_ASSET_ENDPOINT"
        } else {
            Write-Warning "⚠ Not running in Azure Automation - results may not be accurate"
        }
        
        # Connect with Managed Identity
        Write-Output "Connecting with Managed Identity..."
        $context = Connect-AzAccount -Identity -ErrorAction Stop
        
        Write-Output "✓ Successfully authenticated as Managed Identity"
        Write-Output "  Account ID: $($context.Context.Account.Id)"
        Write-Output "  Account Type: $($context.Context.Account.Type)"
        Write-Output "  Tenant ID: $($context.Context.Tenant.Id)"
        
        # Get Graph API token
        Write-Output "Requesting Microsoft Graph access token..."
        $tokenRequest = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        
        if ($tokenRequest.Token) {
            Write-Output "✓ Successfully obtained Graph API token"
            Write-Output "  Token Length: $($tokenRequest.Token.Length) characters"
            Write-Output "  Expires On: $($tokenRequest.ExpiresOn)"
            return $tokenRequest.Token
        } else {
            throw "Failed to obtain access token"
        }
    }
    catch {
        Write-Error "❌ Managed Identity authentication failed: $($_.Exception.Message)"
        throw
    }
}

function Test-GraphPermissions {
    param([string]$AccessToken, [string]$GroupId)
    
    Write-Output ""
    Write-Output "=== Testing Graph API Permissions ==="
    
    $headers = @{
        Authorization  = "Bearer $AccessToken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }
    
    # Test cases with their required permissions
    $tests = @(
        @{
            Name = "Read Service Principal (self)"
            Uri = "https://graph.microsoft.com/v1.0/me"
            Permission = "Application.Read.All or Directory.Read.All"
        },
        @{
            Name = "Read Groups"
            Uri = "https://graph.microsoft.com/v1.0/groups/$GroupId"
            Permission = "Group.Read.All"
        },
        @{
            Name = "Read Group Members"
            Uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
            Permission = "Group.Read.All"
        },
        @{
            Name = "Read Intune Managed Devices"
            Uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=1"
            Permission = "DeviceManagementManagedDevices.ReadWrite.All"
        },
        @{
            Name = "Read Users"
            Uri = "https://graph.microsoft.com/v1.0/users?`$top=1&`$select=id,usageLocation"
            Permission = "User.Read.All"
        }
    )
    
    $passedTests = 0
    $totalTests = $tests.Count
    
    foreach ($test in $tests) {
        Write-Output ""
        Write-Output "Testing: $($test.Name)"
        Write-Output "Required Permission: $($test.Permission)"
        Write-Output "URI: $($test.Uri)"
        
        try {
            $response = Invoke-RestMethod -Uri $test.Uri -Headers $headers -Method Get -ErrorAction Stop
            Write-Output "✓ PASSED"
            $passedTests++
            
            # Show some basic info about the response
            if ($response.value) {
                Write-Output "  Response contains $($response.value.Count) items"
            } elseif ($response.id) {
                Write-Output "  Successfully retrieved object with ID: $($response.id)"
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            Write-Output "❌ FAILED - HTTP $statusCode"
            Write-Output "  Error: $($_.Exception.Message)"
            
            if ($statusCode -eq 401) {
                Write-Output "  💡 This indicates missing Graph API permission: $($test.Permission)"
            } elseif ($statusCode -eq 403) {
                Write-Output "  💡 Permission exists but access denied - check permission type (Application vs Delegated)"
            } elseif ($statusCode -eq 404) {
                Write-Output "  💡 Resource not found - check Group ID or resource existence"
            }
        }
    }
    
    Write-Output ""
    Write-Output "=== Permission Test Summary ==="
    Write-Output "Passed: $passedTests / $totalTests tests"
    
    if ($passedTests -eq $totalTests) {
        Write-Output "✓ All permissions are working correctly!"
        return $true
    } else {
        Write-Output "❌ Some permissions are missing or not working"
        Write-Output ""
        Write-Output "Required Graph API Permissions (Application type):"
        Write-Output "• DeviceManagementManagedDevices.ReadWrite.All"
        Write-Output "• Group.Read.All"
        Write-Output "• User.Read.All"
        Write-Output "• Directory.Read.All"
        Write-Output "• DeviceManagementConfiguration.ReadWrite.All"
        Write-Output "• Application.ReadWrite.All"
        return $false
    }
}

# Main execution
try {
    Write-Output "Microsoft Graph API Permission Test for Azure Automation Managed Identity"
    Write-Output "Group ID to test: $GroupId"
    Write-Output "Test Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
    Write-Output ""
    
    # Test authentication
    $accessToken = Test-ManagedIdentityAuth
    
    # Test permissions
    $permissionsOk = Test-GraphPermissions -AccessToken $accessToken -GroupId $GroupId
    
    Write-Output ""
    Write-Output "=== Final Result ==="
    if ($permissionsOk) {
        Write-Output "✅ Managed Identity is properly configured and has all required permissions"
        Write-Output "The main script should work without authentication issues"
    } else {
        Write-Output "❌ Managed Identity has permission issues that need to be resolved"
        Write-Output "Run the Grant-PermissiontoAzureAAId.ps1 script to fix permissions"
    }
}
catch {
    Write-Error "Test failed: $($_.Exception.Message)"
    Write-Output ""
    Write-Output "=== Troubleshooting Steps ==="
    Write-Output "1. Ensure System-assigned Managed Identity is enabled on the Automation Account"
    Write-Output "2. Run Grant-PermissiontoAzureAAId.ps1 to grant required permissions"
    Write-Output "3. Wait 5-10 minutes after granting permissions for changes to take effect"
    Write-Output "4. Verify the Group ID '$GroupId' exists and contains devices"
}