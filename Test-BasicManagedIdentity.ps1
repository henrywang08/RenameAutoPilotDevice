#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Simple Managed Identity authentication test for Azure Automation.

.DESCRIPTION
    Tests basic Managed Identity authentication and token retrieval.
    Use this to verify that Managed Identity is working before running the full script.
#>

# Load required assemblies
Add-Type -AssemblyName System.Web

Write-Output "=== Simple Managed Identity Test ==="
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

# Check environment
Write-Output "Environment Check:"
Write-Output "  AUTOMATION_ASSET_ENDPOINT: $env:AUTOMATION_ASSET_ENDPOINT"
Write-Output "  MSI_ENDPOINT: $env:MSI_ENDPOINT"
Write-Output "  MSI_SECRET: $(if($env:MSI_SECRET){'[SET]'}else{'[NOT SET]'})"
Write-Output ""

try {
    # Import Az.Accounts
    Write-Output "Importing Az.Accounts module..."
    Import-Module Az.Accounts -Force -ErrorAction Stop
    Write-Output "✓ Az.Accounts imported successfully"
    Write-Output ""
    
    # Method 1: Try Connect-AzAccount with Identity
    Write-Output "=== Method 1: Connect-AzAccount -Identity ==="
    try {
        $context = Connect-AzAccount -Identity -Force -ErrorAction Stop
        Write-Output "✓ Connect-AzAccount succeeded"
        Write-Output "  Account ID: $($context.Context.Account.Id)"
        Write-Output "  Account Type: $($context.Context.Account.Type)"
        Write-Output "  Tenant ID: $($context.Context.Tenant.Id)"
        
        # Try to get token
        Write-Output ""
        Write-Output "Requesting Graph API token..."
        
        try {
            $tokenRequest = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
            Write-Output "✓ Get-AzAccessToken succeeded"
            Write-Output "  Token Length: $($tokenRequest.Token.Length)"
            Write-Output "  Expires On: $($tokenRequest.ExpiresOn)"
            
            # Test the token with a simple Graph call
            Write-Output ""
            Write-Output "Testing token with Graph API call..."
            $headers = @{
                Authorization  = "Bearer $($tokenRequest.Token)"
                'Content-Type' = "application/json"
            }
            
            $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method Get -ErrorAction Stop
            Write-Output "✓ Graph API call succeeded"
            Write-Output "  Service Principal ID: $($response.id)"
            Write-Output "  Display Name: $($response.displayName)"
            
            Write-Output ""
            Write-Output "🎉 SUCCESS: Managed Identity authentication is working correctly!"
            
        }
        catch {
            Write-Output "❌ Get-AzAccessToken failed: $($_.Exception.Message)"
            throw
        }
    }
    catch {
        Write-Output "❌ Connect-AzAccount failed: $($_.Exception.Message)"
        
        # Method 2: Try direct MSI endpoint
        if ($env:MSI_ENDPOINT -and $env:MSI_SECRET) {
            Write-Output ""
            Write-Output "=== Method 2: Direct MSI Endpoint ==="
            try {
                $resource = [System.Web.HttpUtility]::UrlEncode("https://graph.microsoft.com")
                $tokenUri = "$env:MSI_ENDPOINT/?resource=$resource&api-version=2017-09-01"
                $headers = @{ 'Secret' = $env:MSI_SECRET }
                
                Write-Output "Token URI: $tokenUri"
                $response = Invoke-RestMethod -Uri $tokenUri -Headers $headers -Method Get -ErrorAction Stop
                
                Write-Output "✓ Direct MSI call succeeded"
                Write-Output "  Token Type: $($response.token_type)"
                Write-Output "  Token Length: $($response.access_token.Length)"
                Write-Output "  Expires In: $($response.expires_in) seconds"
                
                # Test the token
                Write-Output ""
                Write-Output "Testing token with Graph API call..."
                $graphHeaders = @{
                    Authorization  = "Bearer $($response.access_token)"
                    'Content-Type' = "application/json"
                }
                
                $graphResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphHeaders -Method Get -ErrorAction Stop
                Write-Output "✓ Graph API call succeeded"
                Write-Output "  Service Principal ID: $($graphResponse.id)"
                Write-Output "  Display Name: $($graphResponse.displayName)"
                
                Write-Output ""
                Write-Output "🎉 SUCCESS: Direct MSI authentication is working correctly!"
                
            }
            catch {
                Write-Output "❌ Direct MSI call failed: $($_.Exception.Message)"
                Write-Output "Full error: $($_.Exception.ToString())"
                throw
            }
        } else {
            Write-Output "❌ MSI environment variables not available for fallback"
            throw "All authentication methods failed"
        }
    }
}
catch {
    Write-Output ""
    Write-Output "💥 FAILED: Managed Identity authentication is not working"
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output ""
    Write-Output "Troubleshooting steps:"
    Write-Output "1. Verify System-assigned Managed Identity is enabled on the Automation Account"
    Write-Output "2. Check that the Automation Account has the required permissions"
    Write-Output "3. Wait 5-10 minutes after enabling Managed Identity"
    Write-Output "4. Verify Az.Accounts module is properly installed"
    
    Write-Output ""
    Write-Output "Full error details:"
    Write-Output $_.Exception.ToString()
}

Write-Output ""
Write-Output "=== Test Completed ==="
Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"