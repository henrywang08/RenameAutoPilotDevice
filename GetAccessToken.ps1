Import-Module Az.KeyVault, Az.Accounts

# Configuration
$tenantId = "55f37ed7-ebe7-4cea-8686-1ca9653384f1"
$clientId = "da0eded7-8e16-4a2e-b259-ebbf9396d62a"
$vaultName = "moonappcert"
$certName = "RenameAutoPilotDeviceCert"

# Base64URL encode function
function ConvertTo-Base64Url($text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64.TrimEnd('=').Replace('+','-').Replace('/','_')
}

try {
    # Step 1: Interactive Azure login
    Write-Host "Please sign in to Azure..." -ForegroundColor Yellow
    $azContext = Connect-AzAccount -ErrorAction Stop
    Write-Host "Successfully connected to Azure as: $($azContext.Context.Account.Id)" -ForegroundColor Green
    
    # Step 2: Get certificate with private key from Key Vault
    Write-Host "Getting certificate from Key Vault..." -ForegroundColor Yellow
    $cert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $certName -ErrorAction Stop
    if (-not $cert) {
        throw "Certificate '$certName' not found in Key Vault '$vaultName'"
    }
    Write-Host "Certificate found: $($cert.Name), Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
    
    # Get the certificate secret (contains both public and private key)
    $certSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $certName -AsPlainText -ErrorAction Stop
    
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
    $aud = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    
    # JWT Header with certificate thumbprint
    $thumbprintBytes = [Convert]::FromHexString($cert.Thumbprint.Replace(':', ''))
    $x5t = [Convert]::ToBase64String($thumbprintBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    
    $headerJson = '{"alg":"RS256","typ":"JWT","x5t":"' + $x5t + '"}'
    $payloadJson = '{"aud":"' + $aud + '","iss":"' + $clientId + '","sub":"' + $clientId + '","jti":"' + [guid]::NewGuid().ToString() + '","nbf":' + $nbf + ',"exp":' + $exp + '}'
    
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
        client_id = $clientId
        scope = "https://graph.microsoft.com/.default"
        client_assertion = $clientAssertion
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        grant_type = "client_credentials"
    }
    
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $aud -Body $tokenBody -ErrorAction Stop
    $accessToken = $tokenResponse.access_token
    
    Write-Host "Successfully obtained Graph access token!" -ForegroundColor Green
    Write-Host "Access Token: $accessToken"
    
    # Step 6: Test the token with a simple endpoint that requires minimal permissions
    Write-Host "Testing token with Microsoft Graph..." -ForegroundColor Yellow
    $graphHeaders = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }
    
    try {
        # Try a simple endpoint that usually works with basic app permissions
        $testResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
        if ($testResponse) {
            Write-Host "Token validation successful!" -ForegroundColor Green
        }
    }
    catch {
        # If /me doesn't work (service principal), try applications endpoint
        try {
            $testResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications" -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
            Write-Host "Token validation successful - Application permissions confirmed!" -ForegroundColor Green
        }
        catch {
            Write-Host "Token obtained successfully but may need additional permissions for Graph API calls." -ForegroundColor Yellow
            Write-Host "This is normal for service principal authentication." -ForegroundColor Yellow
        }
    }
    
    return $accessToken
}
catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    throw
}