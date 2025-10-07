<#
.SYNOPSIS
    Renames AutoPilot devices based on primary user's country location.

.DESCRIPTION
    This script authenticates to Microsoft Graph using certificate-based authentication,
    retrieves devices from a specified Entra ID group, determines each device's primary
    user's country, and renames the device with a country-specific prefix (CMA{CountryCode}-).

.PARAMETER TenantId
    Azure AD Tenant ID (default: hardcoded value)

.PARAMETER ClientId
    Application (Client) ID of the registered Azure AD app (default: hardcoded value)

.PARAMETER KeyVaultName
    Name of the Azure Key Vault containing the authentication certificate (default: hardcoded value)

.PARAMETER CertificateName
    Name of the certificate in Key Vault (default: hardcoded value)

.PARAMETER GroupId
    Object ID of the Entra ID group containing devices to rename (default: hardcoded value)

.EXAMPLE
    .\Rename-AutoPilotDevice.ps1
    Runs the script with default configuration values

.NOTES
    Author: AutoPilot Management Team
    Requires: PowerShell 5.1+, Az.KeyVault, Az.Accounts modules
    Required Graph API permissions:
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementManagedDevices.PrivilegedOperations.All
    - Device.ReadWrite.All
    - Group.Read.All
    - GroupMember.Read.All
    - User.Read.All
#>

[CmdletBinding()]
param(
    [string]$TenantId = "55f37ed7-ebe7-4cea-8686-1ca9653384f1",
    [string]$ClientId = "da0eded7-8e16-4a2e-b259-ebbf9396d62a",
    [string]$KeyVaultName = "moonappcert",
    [string]$CertificateName = "RenameAutoPilotDeviceCert",
    [string]$GroupId = "69e3150d-cf9f-4847-9743-e00c5347929e"
)

#Requires -Modules Az.KeyVault, Az.Accounts

Import-Module Az.KeyVault, Az.Accounts

# Configuration constants
$Script:Config = @{
    DeviceNamePrefix = "CMA"
    MaxDeviceNameLength = 15
    GraphBaseUri = "https://graph.microsoft.com"
}

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
        Write-Host "Device '$OriginalDeviceName' already has the desired name. No rename needed." -ForegroundColor Green
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
        Write-Host "Successfully renamed device '$OriginalDeviceName' to '$NewName'" -ForegroundColor Green
        
        # Reboot device using Graph API
        $rebootUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices/$deviceId/rebootNow"
        Write-Verbose "Initiating reboot for device: $rebootUri"
        Invoke-RestMethod -Uri $rebootUri -Headers $headers -Method Post -ErrorAction Stop
        Write-Host "Reboot initiated for device '$NewName'" -ForegroundColor Yellow
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
        Accept        = "application/json"
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

function Get-AccessTokenWithCertificate {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$KeyVaultName,
        [string]$CertificateName,
        [string]$Resource = "https://graph.microsoft.com/.default"
    )
    
    
    # Base64URL encode function
    function ConvertTo-Base64Url($text) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        $base64 = [Convert]::ToBase64String($bytes)
        return $base64.TrimEnd('=').Replace('+','-').Replace('/','_')
    }

    try {
        # Step 1: Interactive Azure login
        Write-Host "Please sign in to Azure..." -ForegroundColor Yellow
        # Clear any existing context that might have subscription issues
        $null = Clear-AzContext -Force -ErrorAction SilentlyContinue
        # Connect to Azure for the specific tenant only, let user choose subscription
        $azContext = Connect-AzAccount -TenantId $TenantId -ErrorAction Stop
        Write-Host "Successfully connected to Azure as: $($azContext.Context.Account.Id)" -ForegroundColor Green
        
        # Step 2: Get certificate with private key from Key Vault
        Write-Host "Getting certificate from Key Vault..." -ForegroundColor Yellow
        $cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -ErrorAction Stop
        if (-not $cert) {
            throw "Certificate '$CertificateName' not found in Key Vault '$KeyVaultName'"
        }
        Write-Host "Certificate found: $($cert.Name), Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
        
        # Get the certificate secret (contains both public and private key)
        $certSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -AsPlainText -ErrorAction Stop
        
        # Convert to X509Certificate2 object with private key
        $certBytes = [Convert]::FromBase64String($certSecret)
        $x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes, "", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        if (-not $x509Cert.HasPrivateKey) {
            throw "Certificate does not contain a private key"
        }
        
        # Step 3: Create JWT for client assertion
        Write-Host "Creating JWT client assertion..." -ForegroundColor Yellow
        
        $now = [System.DateTimeOffset]::UtcNow
        $exp = $now.AddMinutes(120).ToUnixTimeSeconds()
        $nbf = $now.ToUnixTimeSeconds()
        $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        # JWT Header with certificate thumbprint
        $thumbprintBytes = [Convert]::FromHexString($x509Cert.Thumbprint.Replace(':', ''))
        $x5t = [Convert]::ToBase64String($thumbprintBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        
        $headerJson = '{"alg":"RS256","typ":"JWT","x5t":"' + $x5t + '"}'
        $payloadJson = '{"aud":"' + $aud + '","iss":"' + $ClientId + '","sub":"' + $ClientId + '","jti":"' + [guid]::NewGuid().ToString() + '","nbf":' + $nbf + ',"exp":' + $exp + '}'
        
        # Encode header and payload
        $headerEncoded = ConvertTo-Base64Url $headerJson
        $payloadEncoded = ConvertTo-Base64Url $payloadJson
        $jwtUnsigned = "$headerEncoded.$payloadEncoded"
        
        # Step 4: Sign JWT using the private key
        Write-Host "Signing JWT with certificate private key..." -ForegroundColor Yellow
        
        # Get RSA private key from certificate (compatible approach)
        $rsa = $null
        try {
            # Try newer method first
            $rsa = $x509Cert.GetRSAPrivateKey()
        }
        catch {
            # Fallback to older method
            $rsa = $x509Cert.PrivateKey
        }
        
        if (-not $rsa) {
            throw "Unable to get RSA private key from certificate"
        }
        
        # Hash and sign the JWT
        $jwtBytes = [Text.Encoding]::UTF8.GetBytes($jwtUnsigned)
        
        # Sign data using RSA with SHA256
        if ($rsa.GetType().Name -eq "RSACryptoServiceProvider") {
            # For RSACryptoServiceProvider
            $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($jwtBytes)
            $signature = $rsa.SignHash($hash, [System.Security.Cryptography.CryptoConfig]::MapNameToOID("SHA256"))
        } else {
            # For RSA (newer types)
            $signature = $rsa.SignData($jwtBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        
        $signatureEncoded = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+','-').Replace('/','_')
        
        # Complete JWT
        $clientAssertion = "$jwtUnsigned.$signatureEncoded"
        
        # Clean up certificate from memory
        $x509Cert.Dispose()
        
        # Step 5: Get Graph access token using certificate authentication
        Write-Host "Getting Microsoft Graph access token..." -ForegroundColor Yellow
        
        $tokenBody = @{
            client_id = $ClientId
            scope = $Resource
            client_assertion = $clientAssertion
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            grant_type = "client_credentials"
        }
        
        $tokenResponse = Invoke-RestMethod -Method Post -Uri $aud -Body $tokenBody -ErrorAction Stop
        $accessToken = $tokenResponse.access_token
        
        Write-Host "Successfully obtained Graph access token!" -ForegroundColor Green
        
        return $accessToken
    }
    catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        throw
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

    try {
        # Get device information including primary user
        $deviceUri = "$($Script:Config.GraphBaseUri)/beta/deviceManagement/managedDevices" + "?`$filter=deviceName eq '$DeviceName'"
        $headers = @{
            Authorization = "Bearer $AccessToken"
            Accept        = "application/json"
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

# Validate parameters
if ([string]::IsNullOrEmpty($GroupId) -or $GroupId -eq "<your-group-id>") {
    Write-Error "Please provide a valid Group ID parameter."
    Write-Host "You can find the Group ID in the Azure Portal or using Graph API." -ForegroundColor Yellow
    Write-Host "Example: .\Rename-AutoPilotDevice.ps1 -GroupId '12345678-1234-1234-1234-123456789012'" -ForegroundColor Yellow
    exit 1
}

try {
    Write-Host "=== AutoPilot Device Rename Process Started ===" -ForegroundColor Cyan
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Gray
    Write-Host "Group ID: $GroupId" -ForegroundColor Gray
    Write-Host ""

    # Get access token
    $accessToken = Get-AccessTokenWithCertificate -TenantId $TenantId -ClientId $ClientId -KeyVaultName $KeyVaultName -CertificateName $CertificateName

    # Get devices from Entra ID group
    Write-Host "Getting devices from Entra ID group..." -ForegroundColor Yellow
    $groupUri = "$($Script:Config.GraphBaseUri)/v1.0/groups/$GroupId/members"
    $headers = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json"
    }
    $groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get -ErrorAction Stop

    # Filter and process only device members
    $devices = $groupResponse.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }
    
    if (-not $devices) {
        Write-Warning "No devices found in the specified group."
        exit 0
    }

    Write-Host "Found $($devices.Count) device(s) in the group" -ForegroundColor Green
    Write-Host ""

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

            Write-Host "[$deviceCount/$($devices.Count)] Processing: '$originalDeviceName'" -ForegroundColor White
            
            # Get country code for the device's primary user
            $countryCode = Get-DevicePrimaryUserCountryCode -DeviceName $originalDeviceName -AccessToken $accessToken
            
            # Generate new device name
            $newName = New-DeviceName -OriginalDeviceName $originalDeviceName -CountryCode $countryCode
            
            if ($originalDeviceName -eq $newName) {
                Write-Host "  ✓ Device already has correct name format" -ForegroundColor Green
                $skippedCount++
            } else {
                # Rename the device
                Rename-Device -OriginalDeviceName $originalDeviceName -NewName $newName -AccessToken $accessToken
                Write-Host "  ✓ Renamed '$originalDeviceName' → '$newName'" -ForegroundColor Green
                $successCount++
            }
        }
        catch {
            Write-Host "  ✗ Failed to process '$originalDeviceName': $($_.Exception.Message)" -ForegroundColor Red
            $failureCount++
        }
        
        Write-Host ""
    }

    # Display summary
    Write-Host "=== PROCESS SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total devices: $deviceCount" -ForegroundColor White
    Write-Host "Successfully renamed: $successCount" -ForegroundColor Green
    Write-Host "Already correct: $skippedCount" -ForegroundColor Yellow
    Write-Host "Failed: $failureCount" -ForegroundColor Red
    
    if ($failureCount -eq 0) {
        Write-Host "All devices processed successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Warning "Some devices failed to process. Check the errors above."
        exit 1
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Please check your configuration and try again." -ForegroundColor Yellow
    exit 1
}

#endregion