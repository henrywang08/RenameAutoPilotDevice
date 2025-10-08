#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Detailed Graph API request diagnostic for Azure Automation Managed Identity.

.DESCRIPTION
    Analyzes the exact issue with Graph API requests to identify why we're getting 400 Bad Request.
#>

# Load required assemblies
Add-Type -AssemblyName System.Web

Write-Output "=== Detailed Graph API Diagnostic ==="
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

try {
    # Import Az.Accounts
    Import-Module Az.Accounts -Force -ErrorAction Stop
    Write-Output "✓ Az.Accounts imported successfully"
    
    # Connect with Managed Identity
    $context = Connect-AzAccount -Identity -Force -ErrorAction Stop
    Write-Output "✓ Connected as Managed Identity: $($context.Context.Account.Id)"
    
    # Get token
    $tokenRequest = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    Write-Output "✓ Token obtained successfully"
    Write-Output "  Token Length: $($tokenRequest.Token.Length)"
    Write-Output "  Token Preview: $($tokenRequest.Token.Substring(0, 50))..."
    Write-Output ""
    
    # Analyze the token structure
    $tokenParts = $tokenRequest.Token.Split('.')
    Write-Output "Token Analysis:"
    Write-Output "  Parts: $($tokenParts.Count) (should be 3 for JWT)"
    Write-Output "  Header Length: $($tokenParts[0].Length)"
    Write-Output "  Payload Length: $($tokenParts[1].Length)"
    Write-Output "  Signature Length: $($tokenParts[2].Length)"
    Write-Output ""
    
    # Test different Graph API endpoints with detailed error reporting
    $testEndpoints = @(
        @{
            Name = "Service Principal Info (/me)"
            Uri = "https://graph.microsoft.com/v1.0/me"
            Method = "GET"
        },
        @{
            Name = "Service Principal Info (/servicePrincipals/me)"
            Uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$(($context.Context.Account.Id -split '@')[0])"
            Method = "GET"
        },
        @{
            Name = "Applications List (top 1)"
            Uri = "https://graph.microsoft.com/v1.0/applications?`$top=1"
            Method = "GET"
        },
        @{
            Name = "Directory Objects"
            Uri = "https://graph.microsoft.com/v1.0/directoryObjects?`$top=1"
            Method = "GET"
        }
    )
    
    foreach ($endpoint in $testEndpoints) {
        Write-Output "=== Testing: $($endpoint.Name) ==="
        Write-Output "URI: $($endpoint.Uri)"
        Write-Output "Method: $($endpoint.Method)"
        
        # Test with minimal headers first
        Write-Output ""
        Write-Output "Test 1: Minimal headers (Authorization only)"
        try {
            $headers1 = @{
                Authorization = "Bearer $($tokenRequest.Token)"
            }
            
            $response1 = Invoke-RestMethod -Uri $endpoint.Uri -Headers $headers1 -Method $endpoint.Method -ErrorAction Stop
            Write-Output "✓ SUCCESS with minimal headers"
            if ($response1.id) {
                Write-Output "  Object ID: $($response1.id)"
            }
            if ($response1.displayName) {
                Write-Output "  Display Name: $($response1.displayName)"
            }
            if ($response1.value) {
                Write-Output "  Items returned: $($response1.value.Count)"
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
            Write-Output "❌ FAILED with minimal headers - HTTP $statusCode"
            Write-Output "  Error: $($_.Exception.Message)"
            
            # Try to get response body for more details
            if ($_.Exception.Response) {
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseBody = $reader.ReadToEnd()
                    Write-Output "  Response Body: $responseBody"
                }
                catch {
                    Write-Output "  Could not read response body"
                }
            }
        }
        
        Write-Output ""
        Write-Output "Test 2: Full headers (Authorization + Content-Type + Accept)"
        try {
            $headers2 = @{
                Authorization  = "Bearer $($tokenRequest.Token)"
                'Content-Type' = "application/json"
                Accept         = "application/json"
            }
            
            $response2 = Invoke-RestMethod -Uri $endpoint.Uri -Headers $headers2 -Method $endpoint.Method -ErrorAction Stop
            Write-Output "✓ SUCCESS with full headers"
            if ($response2.id) {
                Write-Output "  Object ID: $($response2.id)"
            }
            if ($response2.displayName) {
                Write-Output "  Display Name: $($response2.displayName)"
            }
            if ($response2.value) {
                Write-Output "  Items returned: $($response2.value.Count)"
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
            Write-Output "❌ FAILED with full headers - HTTP $statusCode"
            Write-Output "  Error: $($_.Exception.Message)"
            
            # Try to get response body for more details
            if ($_.Exception.Response) {
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $responseBody = $reader.ReadToEnd()
                    Write-Output "  Response Body: $responseBody"
                }
                catch {
                    Write-Output "  Could not read response body"
                }
            }
        }
        
        Write-Output ""
        Write-Output "Test 3: Alternative User-Agent"
        try {
            $headers3 = @{
                Authorization = "Bearer $($tokenRequest.Token)"
                'User-Agent'  = "PowerShell/7.0 (Azure-Automation)"
                Accept        = "application/json"
            }
            
            $response3 = Invoke-RestMethod -Uri $endpoint.Uri -Headers $headers3 -Method $endpoint.Method -ErrorAction Stop
            Write-Output "✓ SUCCESS with User-Agent header"
            if ($response3.id) {
                Write-Output "  Object ID: $($response3.id)"
            }
            if ($response3.displayName) {
                Write-Output "  Display Name: $($response3.displayName)"
            }
            if ($response3.value) {
                Write-Output "  Items returned: $($response3.value.Count)"
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
            Write-Output "❌ FAILED with User-Agent - HTTP $statusCode"
            Write-Output "  Error: $($_.Exception.Message)"
        }
        
        Write-Output ""
        Write-Output "================================================"
        Write-Output ""
    }
    
    # Test token validity by decoding (basic check)
    Write-Output "=== Token Validation ==="
    try {
        # Decode the header (first part)
        $headerBytes = [Convert]::FromBase64String(($tokenParts[0] + "===").Substring(0, ($tokenParts[0].Length + 3) -band -4))
        $header = [System.Text.Encoding]::UTF8.GetString($headerBytes)
        Write-Output "Token Header: $header"
        
        # Decode the payload (second part) 
        $payloadBytes = [Convert]::FromBase64String(($tokenParts[1] + "===").Substring(0, ($tokenParts[1].Length + 3) -band -4))
        $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        Write-Output "Token Payload: $payload"
        
        # Parse payload JSON to check claims
        $claims = $payload | ConvertFrom-Json
        Write-Output ""
        Write-Output "Key Token Claims:"
        Write-Output "  Audience (aud): $($claims.aud)"
        Write-Output "  Issuer (iss): $($claims.iss)"
        Write-Output "  Subject (sub): $($claims.sub)"
        Write-Output "  App ID (appid): $($claims.appid)"
        Write-Output "  Expires (exp): $($claims.exp) ($(Get-Date -UnixTimeSeconds $claims.exp))"
        Write-Output "  Not Before (nbf): $($claims.nbf) ($(Get-Date -UnixTimeSeconds $claims.nbf))"
        Write-Output "  Roles: $($claims.roles -join ', ')"
        Write-Output "  Scopes: $($claims.scp)"
        
    }
    catch {
        Write-Output "Could not decode token: $($_.Exception.Message)"
    }
}
catch {
    Write-Output "❌ Script failed: $($_.Exception.Message)"
    Write-Output "Full error: $($_.Exception.ToString())"
}

Write-Output ""
Write-Output "=== Diagnostic Completed ==="
Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"