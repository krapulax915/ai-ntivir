# Signs the AI-NTIVIR installer (and optionally AI-NTIVIR.exe) via the SignPath.io REST API.
# Usage:
#   powershell -ExecutionPolicy Bypass -File installer\sign_with_signpath.ps1 -File "installer\output\AI-NTIVIR-Setup-1.0.0.exe"
#
# Requires installer\signpath_config.json (copy from signpath_config.template.json and fill in):
#   ApiToken, OrganizationId, ProjectId, SigningPolicyId
#
# The private key of your SignPath test certificate (MyApp_Test_Certificate) stays in
# SignPath's HSM - only the signed artifact travels, never the key.

param(
    [Parameter(Mandatory = $true)]
    [string]$File,

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'signpath_config.json')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Missing config: $ConfigPath. Copy signpath_config.template.json to signpath_config.json and fill in ApiToken, OrganizationId, ProjectId, SigningPolicyId."
}

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$apiToken = $cfg.ApiToken
$orgId = $cfg.OrganizationId
$projectId = $cfg.ProjectId
$policyId = $cfg.SigningPolicyId

if ($apiToken -like 'PASTE_*') { Write-Error "Fill in signpath_config.json first." }

$apiBase = "https://api.signpath.io/v1/organizations/$orgId"

# 1. Pack the file into a zip (SignPath submits/returns zip artifacts)
$zipPath = [System.IO.Path]::ChangeExtension($File, '.zip')
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $File -DestinationPath $zipPath

Write-Host "Submitting signing request for $(Split-Path $File -Leaf) ..."
$headers = @{ Authorization = "Bearer $apiToken" }

# 2. Create the signing request
$createUri = "$apiBase/signing-requests`?project-id=$projectId&signing-policy-id=$policyId"
$response = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -InFile $zipPath -ContentType 'application/zip'

$requestId = $response.id
Write-Host "Signing request created: $requestId (status: $($response.status))"

# 3. Poll until completed
$maxWaitSec = 600
$waited = 0
while ($response.status -in @('InProgress', 'WaitingForFeedback')) {
    Start-Sleep -Seconds 5
    $waited += 5
    if ($waited -gt $maxWaitSec) { throw "Signing timed out after $maxWaitSec s" }
    $response = Invoke-RestMethod -Method Get -Uri "$apiBase/signing-requests/$requestId" -Headers $headers
    Write-Host "  status: $($response.status)"
}

if ($response.status -ne 'Completed') {
    throw "Signing failed with status: $($response.status) - $($response | ConvertTo-Json -Depth 5)"
}

# 4. Download the signed artifact
$signedZip = [System.IO.Path]::ChangeExtension($File, '.signed.zip')
Invoke-WebRequest -Uri "$apiBase/signing-requests/$requestId/signed-artifact" -Headers $headers -OutFile $signedZip

# 5. Replace the original with the signed file
$signedExtractDir = Join-Path $env:TEMP ("signpath_" + [guid]::NewGuid())
Expand-Archive -Path $signedZip -DestinationPath $signedExtractDir
$signedFile = Get-ChildItem $signedExtractDir -Recurse -File | Select-Object -First 1
Copy-Item $signedFile.FullName $File -Force

Remove-Item $signedZip -Force -ErrorAction SilentlyContinue
Remove-Item $signedExtractDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "SIGNED OK: $File" -ForegroundColor Green
Write-Host "Signature check: Get-AuthenticodeSignature '$File' | Format-List"
