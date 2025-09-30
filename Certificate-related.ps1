$cert = New-SelfSignedCertificate `
  -DnsName "renameautopilotdevice.moon.marsone.sg" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable `
  -KeySpec Signature `
  -KeyLength 2048 `
  -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears(2) `
  -FriendlyName "RenameAutoPilotDeviceCert"

$inputString = Read-Host "Please enter a password to protect the PFX file"
$mypwd = ConvertTo-SecureString -String $inputString -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\RenameAutoPilotDeviceCert.pfx" -Password $mypwd

Export-Certificate -Cert $cert -FilePath ".\RenameAutoPilotDeviceCert.cer"

