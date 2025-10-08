<#
.SYNOPSIS
    Grants Microsoft Graph API permissions to an Azure Managed Identity.

.DESCRIPTION
    This script connects to Microsoft Graph and assigns the required permissions
    to a specified Managed Identity for AutoPilot device management operations.

.PARAMETER ManagedIdentityName
    The display name of the Managed Identity to grant permissions to.

.EXAMPLE
    .\Grant-PermissiontoAzureAAId.ps1 -ManagedIdentityName "MyAutomationAccount"

.NOTES
    Requires Microsoft.Graph.Authentication and Microsoft.Graph.Applications modules
    User must have sufficient privileges to grant application permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ManagedIdentityName = "sgAutomationAccount"
)

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    Write-Host "Successfully imported Microsoft Graph modules" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import required modules. Please install Microsoft.Graph modules first:"
    Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

# Connect to Microsoft Graph with required scopes
try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "Requesting elevated permissions for application role assignment..." -ForegroundColor Gray
    
    # Multiple scopes are required for granting app permissions to service principals
    $requiredScopes = @(
        "Application.ReadWrite.All",           # Read and write applications
        "AppRoleAssignment.ReadWrite.All",     # Assign app roles to service principals
        "Directory.ReadWrite.All"              # Read and write directory objects (may be needed)
    )
    
    Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
    Write-Host "Successfully connected to Microsoft Graph with elevated scopes" -ForegroundColor Green
    
    # Verify current permissions
    $context = Get-MgContext
    Write-Host "Current scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
    
    # Check if user has required admin roles
    Write-Host "`nVerifying user permissions..." -ForegroundColor Yellow
    try {
        $currentUser = Get-MgContext
        $me = Get-MgUser -UserId $currentUser.Account -ErrorAction SilentlyContinue
        
        if ($me) {
            Write-Host "Authenticated as: $($me.DisplayName) ($($me.UserPrincipalName))" -ForegroundColor Gray
            
            # Check for admin roles (requires additional scope, but let's try)
            try {
                $adminRoles = Get-MgUserMemberOf -UserId $me.Id -ErrorAction SilentlyContinue
                $hasGlobalAdmin = $adminRoles | Where-Object { $_.DisplayName -eq "Global Administrator" }
                $hasPrivilegedRole = $adminRoles | Where-Object { $_.DisplayName -eq "Privileged Role Administrator" }
                $hasAppAdmin = $adminRoles | Where-Object { $_.DisplayName -eq "Application Administrator" }
                
                if ($hasGlobalAdmin -or $hasPrivilegedRole -or $hasAppAdmin) {
                    Write-Host "✅ User has sufficient admin privileges" -ForegroundColor Green
                } else {
                    Write-Warning "⚠️  User may not have sufficient admin privileges"
                    Write-Host "Required roles: Global Administrator, Privileged Role Administrator, or Application Administrator" -ForegroundColor Gray
                }
            }
            catch {
                Write-Host "Unable to verify admin roles (this is normal)" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "Unable to retrieve current user info" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Ensure your account has Global Administrator or Privileged Role Administrator role" -ForegroundColor Gray
    Write-Host "2. You may need to consent to additional permissions in the browser" -ForegroundColor Gray
    Write-Host "3. Try disconnecting first: Disconnect-MgGraph" -ForegroundColor Gray
    exit 1
}

# Variables
$graphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph App ID

Write-Host "`nSearching for Managed Identity: '$ManagedIdentityName'" -ForegroundColor Yellow

# Get Managed Identity Service Principal
try {
    Write-Host "Searching for Managed Identity Service Principal..." -ForegroundColor Yellow
    $managedIdentity = Get-MgServicePrincipal -Filter "displayName eq '$ManagedIdentityName'" -ErrorAction Stop
    
    if (-not $managedIdentity) {
        Write-Warning "No Managed Identity found with display name: '$ManagedIdentityName'"
        Write-Host "`nTrying alternative search methods..." -ForegroundColor Yellow
        
        # Try searching with partial match
        $allServicePrincipals = Get-MgServicePrincipal -All | Where-Object { $_.DisplayName -like "*$ManagedIdentityName*" }
        
        if ($allServicePrincipals) {
            Write-Host "Found similar service principals:" -ForegroundColor Cyan
            foreach ($sp in $allServicePrincipals) {
                Write-Host "  - Name: '$($sp.DisplayName)', ID: $($sp.Id), Type: $($sp.ServicePrincipalType)" -ForegroundColor Gray
            }
            
            # Use the first match that looks like a managed identity
            $managedIdentity = $allServicePrincipals | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" } | Select-Object -First 1
            
            if ($managedIdentity) {
                Write-Host "Using Managed Identity: '$($managedIdentity.DisplayName)'" -ForegroundColor Green
            }
        }
        
        if (-not $managedIdentity) {
            Write-Error "Could not find any Managed Identity matching '$ManagedIdentityName'"
            Write-Host "`nAvailable Managed Identities:" -ForegroundColor Yellow
            $allManagedIdentities = Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" }
            if ($allManagedIdentities) {
                foreach ($mi in $allManagedIdentities) {
                    Write-Host "  - $($mi.DisplayName)" -ForegroundColor Gray
                }
            } else {
                Write-Host "  No Managed Identities found in this tenant" -ForegroundColor Gray
            }
            exit 1
        }
    } else {
        Write-Host "Found Managed Identity: '$($managedIdentity.DisplayName)' (ID: $($managedIdentity.Id))" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to retrieve Managed Identity: $($_.Exception.Message)"
    exit 1
}

# Get Microsoft Graph Service Principal
try {
    Write-Host "`nSearching for Microsoft Graph Service Principal..." -ForegroundColor Yellow
    $graphSPN = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    
    if (-not $graphSPN) {
        Write-Error "Could not find Microsoft Graph Service Principal"
        exit 1
    }
    
    Write-Host "Found Microsoft Graph Service Principal (ID: $($graphSPN.Id))" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve Microsoft Graph Service Principal: $($_.Exception.Message)"
    exit 1
}

# Define required permissions
$permissions = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "Device.ReadWrite.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "User.Read.All"
)

Write-Host "`nRequired permissions:" -ForegroundColor Yellow
foreach ($perm in $permissions) {
    Write-Host "  - $perm" -ForegroundColor Gray
}

# Check existing permissions first
Write-Host "`nChecking existing permissions..." -ForegroundColor Yellow
try {
    $existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id
    $existingPermissions = @()
    
    foreach ($assignment in $existingAssignments) {
        if ($assignment.ResourceId -eq $graphSPN.Id) {
            $appRole = $graphSPN.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
            if ($appRole) {
                $existingPermissions += $appRole.Value
                Write-Host "  ✓ Already has: $($appRole.Value)" -ForegroundColor Green
            }
        }
    }
}
catch {
    Write-Warning "Could not check existing permissions: $($_.Exception.Message)"
    $existingPermissions = @()
}

# Assign missing permissions
$successCount = 0
$failureCount = 0
$skippedCount = 0

Write-Host "`nAssigning permissions..." -ForegroundColor Yellow
foreach ($perm in $permissions) {
    try {
        # Check if permission already exists
        if ($existingPermissions -contains $perm) {
            Write-Host "  ⏭️  Skipped: $perm (already assigned)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }
        
        # Find the app role for this permission
        $appRole = $graphSPN.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" }
        
        if (-not $appRole) {
            Write-Host "  ❌ Failed: $perm (permission not found in Microsoft Graph App Roles)" -ForegroundColor Red
            $failureCount++
            continue
        }
        
        # Assign the permission
        Write-Host "  🔄 Assigning: $perm..." -ForegroundColor Cyan -NoNewline
        
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $managedIdentity.Id `
            -PrincipalId $managedIdentity.Id `
            -ResourceId $graphSPN.Id `
            -AppRoleId $appRole.Id `
            -ErrorAction Stop | Out-Null
            
        Write-Host " ✅ Success" -ForegroundColor Green
        $successCount++
        
        # Small delay to avoid throttling
        Start-Sleep -Milliseconds 500
    }
    catch {
        Write-Host " ❌ Failed" -ForegroundColor Red
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
        $failureCount++
    }
}

# Summary
Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "PERMISSION ASSIGNMENT SUMMARY" -ForegroundColor Cyan
Write-Host "="*50 -ForegroundColor Cyan
Write-Host "Managed Identity: $($managedIdentity.DisplayName)" -ForegroundColor White
Write-Host "Total Permissions: $($permissions.Count)" -ForegroundColor White
Write-Host "Successfully Assigned: $successCount" -ForegroundColor Green
Write-Host "Already Assigned: $skippedCount" -ForegroundColor Yellow
Write-Host "Failed: $failureCount" -ForegroundColor Red

if ($failureCount -eq 0) {
    Write-Host "`n🎉 All permissions have been successfully configured!" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Some permissions failed to assign. Please check the errors above." -ForegroundColor Yellow
}

# Disconnect from Microsoft Graph
try {
    Disconnect-MgGraph | Out-Null
    Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Gray
}
catch {
    # Ignore disconnect errors
}
