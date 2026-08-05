[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SignTool,
    [Parameter(Mandatory = $true)][string]$ArtifactSigningDlib,
    [Parameter(Mandatory = $true)][string]$MetadataFile,
    [Parameter(Mandatory = $true)][string[]]$Files
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($required in @($SignTool, $ArtifactSigningDlib, $MetadataFile)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required signing input is missing: $required"
    }
}

foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Signing target is missing: $file"
    }
    & $SignTool sign /v /debug /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib $ArtifactSigningDlib /dmdf $MetadataFile $file
    if ($LASTEXITCODE -ne 0) {
        throw "Artifact Signing failed for $file with exit code $LASTEXITCODE."
    }
    & $SignTool verify /pa /all /v $file
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode verification failed for $file with exit code $LASTEXITCODE."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "Technology Biased LLC") {
        throw "The signature did not verify as Technology Biased LLC: $file"
    }
}
