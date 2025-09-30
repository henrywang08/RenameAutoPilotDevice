# Install-Module -Name Az.KeyVault -Force -AllowClobber
# Install-Module -Name Az.KeyVault -Force -AllowClobber
Import-Module Az.KeyVault, Az.Accounts

function NewDeviceName {
    param (
        [string]$OriginalDeviceName,
        [string]$CountryCode
    )

    # Validate country code format (ISO 3166-1 alpha-2)
    if ($CountryCode -notmatch '^[A-Z]{2}$') {
        throw "Country code must be 2 uppercase letters (ISO 3166-1 alpha-2)."
    }

    # Check if device name already contains country code in "CMAXX-" format
    if ($OriginalDeviceName -match "^CMA$CountryCode-") {
        $NewName = $OriginalDeviceName
    } else {
        # Get the right part of the device name starting from the 4th character (index 3)
        $RightPart = $OriginalDeviceName.Substring(3)
        $NewName = "CMA$CountryCode-$RightPart"
    }

    # Trim to 15 characters if longer
    if ($NewName.Length -gt 15) {
        $NewName = $NewName.Substring(0, 15)
    }

    return $NewName
}

function RenameDevice {
    param (
        [string]$OriginalDeviceName,
        [string]$NewName,
        [string]$AccessToken
    )

    if ($OriginalDeviceName -eq $NewName) {
        Write-Host "Device '$OriginalDeviceName' already has the desired name '$NewName'. No rename needed."
        return
    }

    # Get device ID from Graph API using OriginalDeviceName
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$OriginalDeviceName'"
    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = "application/json"
    }
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    if (!$response.value -or $response.value.Count -eq 0) {
        throw "Device with name '$OriginalDeviceName' not found."
    }
    $deviceId = $response.value[0].id

    # Rename device using Graph API
    $renameUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/setDeviceName"
    $body = @{
        "deviceName" = $NewName
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $renameUri -Headers $headers -Method Post -Body $body

    # Reboot device using Graph API
    $rebootUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceId/rebootNow"
    Invoke-RestMethod -Uri $rebootUri -Headers $headers -Method Post

    Write-Host "Device '$OriginalDeviceName' renamed to '$NewName' and reboot initiated."
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
        $exp = $now.AddMinutes(10).ToUnixTimeSeconds()
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
    param (
        [string]$OriginalDeviceName,
        [string]$AccessToken
    )

    # Get device info from Graph API
    $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=deviceName eq '$OriginalDeviceName'"
    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = "application/json"
    }
    $deviceResponse = Invoke-RestMethod -Uri $deviceUri -Headers $headers -Method Get
    if (!$deviceResponse.value -or $deviceResponse.value.Count -eq 0) {
        throw "Device with name '$OriginalDeviceName' not found."
    }
    $userId = $deviceResponse.value[0].userId
    if (-not $userId) {
        throw "Primary user not found for device '$OriginalDeviceName'."
    }

    # Get user info from Graph API
     $userUri = "https://graph.microsoft.com/v1.0/users/$userId?`$select=usageLocation"
        # Test the code. 
        # $userUri = "https://graph.microsoft.com/v1.0/users/a31381bd-85ec-44bf-bd4f-c7e1d0e33b59"
    $userResponse = Invoke-RestMethod -Uri $userUri -Headers $headers -Method Get
    $country = $userResponse.usageLocation
    if (-not $country) {
        throw "Usage Location property not found for user '$userId'."
    }

    # Return ISO country code (assume country property is ISO 3166-1 alpha-2)
    return $country
}

# Main script logic
# Variables
$TenantId       = "55f37ed7-ebe7-4cea-8686-1ca9653384f1"
$ClientId       = "da0eded7-8e16-4a2e-b259-ebbf9396d62a"
$KeyVaultName   = "moonappcert"
$CertificateName= "RenameAutoPilotDeviceCert"
$GroupId        = "69e3150d-cf9f-4847-9743-e00c5347929e"  # Set your actual group ID here

# Get access token
$AccessToken = Get-AccessTokenWithCertificate -TenantId $TenantId -ClientId $ClientId -KeyVaultName $KeyVaultName -CertificateName $CertificateName

# Check if GroupId is provided
if ([string]::IsNullOrEmpty($GroupId) -or $GroupId -eq "<your-group-id>") {
    Write-Host "Please provide a valid Group ID in the `$GroupId variable." -ForegroundColor Red
    Write-Host "You can find the Group ID in the Azure Portal or using Graph API." -ForegroundColor Yellow
    Write-Host "Example: `$GroupId = '12345678-1234-1234-1234-123456789012'" -ForegroundColor Yellow
    return
}

Write-Host "Getting devices from Entra ID group: $GroupId" -ForegroundColor Yellow

# Get devices in Entra ID group
$groupUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
$headers = @{
    Authorization = "Bearer $AccessToken"
    Accept        = "application/json"
}
$groupResponse = Invoke-RestMethod -Uri $groupUri -Headers $headers -Method Get

foreach ($member in $groupResponse.value) {
    if ($member.'@odata.type' -eq "#microsoft.graph.device") {
        $OriginalDeviceName = $member.displayName

        try {
            $CountryCode = Get-DevicePrimaryUserCountryCode -OriginalDeviceName $OriginalDeviceName -AccessToken $AccessToken
            $NewName = NewDeviceName -OriginalDeviceName $OriginalDeviceName -CountryCode $CountryCode
            RenameDevice -OriginalDeviceName $OriginalDeviceName -NewName $NewName -AccessToken $AccessToken
            Write-Host "Renamed '$OriginalDeviceName' to '$NewName'"
        } catch {
            Write-Warning "Failed to rename '$OriginalDeviceName': $_"
        }
    }
}