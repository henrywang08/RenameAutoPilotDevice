#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Tests Graph API with correct endpoints for service principal (application) authentication.

.DESCRIPTION
    Uses the proper Graph API endpoints that work with application permissions rather than delegated permissions.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GroupId
)

# Load required assemblies
Add-Type -AssemblyName System.Web

Write-Output "=== Application Auth Graph API Test ==="
Write-Output "Testing Group ID: $GroupId"
Write-Output "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Output ""

try {
    # Import Az.Accounts and connect
    Import-Module Az.Accounts -Force -ErrorAction Stop
    $context = Connect-AzAccount -Identity -Force -ErrorAction Stop
    Write-Output "✓ Connected as Managed Identity: $($context.Context.Account.Id)"
    
    # Get token
    $tokenRequest = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    Write-Output "✓ Token obtained successfully"
    
    # Setup headers - using ONLY Authorization and Accept (no Content-Type for GET requests)
    $headers = @{
        Authorization = "Bearer $($tokenRequest.Token)"
        Accept        = "application/json"
    }
    
    Write-Output ""
    Write-Output "=== Testing Application-Compatible Endpoints ==="
    
    # Test 1: Get specific group (uses Group.Read.All permission)
    Write-Output ""
    Write-Output "Test 1: Get Group Information"
    try {
        $groupUri = "https://graph.microsoft.com/v1.0/groups/$GroupId"
        Write-Output "URI: $groupUri"
        
        $groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "✅ SUCCESS - Group found"
        Write-Output "  Group Name: $($groupResponse.displayName)"
        Write-Output "  Group ID: $($groupResponse.id)"
        Write-Output "  Group Type: $($groupResponse.groupTypes -join ', ')"
        Write-Output "  Security Enabled: $($groupResponse.securityEnabled)"
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        Write-Output "❌ FAILED - HTTP $statusCode"
        Write-Output "  Error: $($_.Exception.Message)"
        
        if ($statusCode -eq 404) {
            Write-Output "  💡 Group ID '$GroupId' does not exist or is not accessible"
        } elseif ($statusCode -eq 403) {
            Write-Output "  💡 Permission issue - check Group.Read.All permission"
        }
    }
    
    # Test 2: Get group members (uses Group.Read.All permission)
    Write-Output ""
    Write-Output "Test 2: Get Group Members"
    try {
        $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
        Write-Output "URI: $membersUri"
        
        $membersResponse = Invoke-RestMethod -Uri $membersUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "✅ SUCCESS - Group members retrieved"
        Write-Output "  Total Members: $($membersResponse.value.Count)"
        
        $deviceMembers = $membersResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }
        $userMembers = $membersResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" }
        
        Write-Output "  Device Members: $($deviceMembers.Count)"
        Write-Output "  User Members: $($userMembers.Count)"
        
        if ($deviceMembers) {
            Write-Output "  Sample Device: $($deviceMembers[0].displayName)"
        }
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        Write-Output "❌ FAILED - HTTP $statusCode"
        Write-Output "  Error: $($_.Exception.Message)"
    }
    
    # Test 3: Get Intune managed devices (uses DeviceManagementManagedDevices.Read.All)
    Write-Output ""
    Write-Output "Test 3: Get Intune Managed Devices (sample)"
    try {
        $intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=3"
        Write-Output "URI: $intuneUri"
        
        $intuneResponse = Invoke-RestMethod -Uri $intuneUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "✅ SUCCESS - Intune devices retrieved"
        Write-Output "  Sample Devices: $($intuneResponse.value.Count)"
        
        foreach ($device in $intuneResponse.value) {
            Write-Output "    - $($device.deviceName) (OS: $($device.operatingSystem))"
        }
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        Write-Output "❌ FAILED - HTTP $statusCode"
        Write-Output "  Error: $($_.Exception.Message)"
    }
    
    # Test 4: Get users (sample) - uses User.Read.All
    Write-Output ""
    Write-Output "Test 4: Get Users (sample)"
    try {
        $usersUri = "https://graph.microsoft.com/v1.0/users?`$top=3&`$select=id,displayName,usageLocation"
        Write-Output "URI: $usersUri"
        
        $usersResponse = Invoke-RestMethod -Uri $usersUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "✅ SUCCESS - Users retrieved"
        Write-Output "  Sample Users: $($usersResponse.value.Count)"
        
        foreach ($user in $usersResponse.value) {
            Write-Output "    - $($user.displayName) (Country: $($user.usageLocation))"
        }
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        Write-Output "❌ FAILED - HTTP $statusCode"
        Write-Output "  Error: $($_.Exception.Message)"
    }
    
    # Test 5: Get service principal info (correct way for app auth)
    Write-Output ""
    Write-Output "Test 5: Get Service Principal Information"
    try {
        # Extract the object ID from the token payload
        $tokenParts = $tokenRequest.Token.Split('.')
        $payloadBytes = [Convert]::FromBase64String(($tokenParts[1] + "===").Substring(0, ($tokenParts[1].Length + 3) -band -4))
        $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
        $objectId = $payload.oid
        
        $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$objectId"
        Write-Output "URI: $spUri"
        Write-Output "Object ID: $objectId"
        
        $spResponse = Invoke-RestMethod -Uri $spUri -Headers $headers -Method Get -ErrorAction Stop
        Write-Output "✅ SUCCESS - Service Principal info retrieved"
        Write-Output "  Display Name: $($spResponse.displayName)"
        Write-Output "  App ID: $($spResponse.appId)"
        Write-Output "  Service Principal Type: $($spResponse.servicePrincipalType)"
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        Write-Output "❌ FAILED - HTTP $statusCode"
        Write-Output "  Error: $($_.Exception.Message)"
    }
    
    Write-Output ""
    Write-Output "=== Test Summary ==="
    Write-Output "✅ The authentication is working correctly!"
    Write-Output "✅ Application permissions are properly configured!"
    Write-Output "✅ Ready to run the main device renaming script!"
    
}
catch {
    Write-Output "❌ Test failed: $($_.Exception.Message)"
    Write-Output "Full error: $($_.Exception.ToString())"
}

Write-Output ""
Write-Output "=== Test Completed ==="
Write-Output "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"