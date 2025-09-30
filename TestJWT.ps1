# Simple JWT test
function ConvertTo-Base64Url($text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $base64 = [Convert]::ToBase64String($bytes)
    return $base64.TrimEnd('=').Replace('+','-').Replace('/','_')
}

$headerJson = '{"alg":"RS256","typ":"JWT","x5t":"test"}'
$payloadJson = '{"aud":"test","iss":"test","sub":"test","jti":"test","nbf":123,"exp":456}'

Write-Host "Header JSON: $headerJson"
Write-Host "Payload JSON: $payloadJson"

$headerEncoded = ConvertTo-Base64Url $headerJson
$payloadEncoded = ConvertTo-Base64Url $payloadJson

Write-Host "Header encoded: $headerEncoded"
Write-Host "Payload encoded: $payloadEncoded"
Write-Host "JWT: $headerEncoded.$payloadEncoded"

# Test decode
$decodedHeader = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($headerEncoded.Replace('-','+').Replace('_','/').PadRight($headerEncoded.Length + (4 - $headerEncoded.Length % 4) % 4, '=')))
Write-Host "Decoded header: $decodedHeader"
