[CmdletBinding()]
param(
    [string]$Python = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$clamAvVersion = "1.5.3"
$installerName = "clamav-$clamAvVersion.win.x64.msi"
$installerUrl = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$clamAvVersion/$installerName"
$expectedHash = "dce5c5eb819d67039043a9d8615d3a03642c7a33d1c517711e42aa0b64a980dd"
$verificationRoot = Join-Path ([System.IO.Path]::GetTempPath()) "aaha-antivirus-live-clamav"
$installerPath = Join-Path $verificationRoot $installerName
$stateRoot = Join-Path $verificationRoot "state"
$scanRoot = Join-Path $verificationRoot "scan"
$evidenceRoot = Join-Path $repoRoot "dist\evidence"
$evidencePath = Join-Path $evidenceRoot "live-clamav-evidence.json"
$provenancePath = Join-Path $evidenceRoot "clamav-provenance.json"
$msiLog = Join-Path $evidenceRoot "clamav-install.log"
$oldLocalAppData = $env:LOCALAPPDATA
$msiexec = Join-Path $env:SystemRoot "System32\msiexec.exe"
$installed = $false

if (Test-Path -LiteralPath $verificationRoot) {
    Remove-Item -LiteralPath $verificationRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $verificationRoot, $stateRoot, $scanRoot, $evidenceRoot -Force | Out-Null

try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    $actualHash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "ClamAV installer SHA-256 mismatch."
    }
    $installerSignature = Get-AuthenticodeSignature -LiteralPath $installerPath
    if ($installerSignature.Status -ne 'Valid') {
        throw "The official ClamAV installer has Authenticode status $($installerSignature.Status)."
    }
    if ($installerSignature.SignerCertificate.Subject -notmatch 'Cisco') {
        throw "The official ClamAV installer signer was not Cisco: $($installerSignature.SignerCertificate.Subject)"
    }

    $installArguments = @(
        "/i",
        "`"$installerPath`"",
        "/qn",
        "/norestart",
        "REBOOT=ReallySuppress",
        "/L*v",
        "`"$msiLog`""
    )
    $installProcess = Start-Process -FilePath $msiexec -ArgumentList $installArguments -PassThru -Wait
    if ($installProcess.ExitCode -notin @(0, 3010)) {
        throw "ClamAV installation failed with exit code $($installProcess.ExitCode)."
    }
    $installed = $true

    $engineRoots = @(
        (Join-Path $env:ProgramFiles "ClamAV"),
        (Join-Path ${env:ProgramFiles(x86)} "ClamAV")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
    $clamscanCandidates = @(
        $engineRoots |
            ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter "clamscan.exe" -File -Recurse }
    )
    if ($clamscanCandidates.Count -ne 1) {
        throw "Expected one installed clamscan.exe; found $($clamscanCandidates.Count)."
    }
    $clamscan = $clamscanCandidates[0].FullName
    $freshclam = Join-Path $clamscanCandidates[0].Directory.FullName "freshclam.exe"
    if (-not (Test-Path -LiteralPath $freshclam -PathType Leaf)) {
        throw "freshclam.exe was not found beside clamscan.exe."
    }

    $env:LOCALAPPDATA = $stateRoot
    & $Python (Join-Path $repoRoot "packaging\live_clamav_check.py") `
        --clamscan $clamscan `
        --freshclam $freshclam `
        --scan-root $scanRoot `
        --evidence $evidencePath
    if ($LASTEXITCODE -ne 0) {
        throw "The live ClamAV adapter check failed with exit code $LASTEXITCODE."
    }

    $provenance = [ordered]@{
        schema_version = 1
        source = $installerUrl
        file = $installerName
        sha256 = $actualHash
        expected_sha256 = $expectedHash
        installer_authenticode = $installerSignature.Status.ToString()
        installer_signer_contains_cisco = $true
    }
    [System.IO.File]::WriteAllText(
        $provenancePath,
        ($provenance | ConvertTo-Json -Depth 3) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
finally {
    $env:LOCALAPPDATA = $oldLocalAppData
    if ($installed) {
        $removeProcess = Start-Process -FilePath $msiexec -ArgumentList @(
            "/x",
            "`"$installerPath`"",
            "/qn",
            "/norestart",
            "REBOOT=ReallySuppress"
        ) -PassThru -Wait
        if ($removeProcess.ExitCode -notin @(0, 3010, 1605)) {
            throw "ClamAV cleanup failed with exit code $($removeProcess.ExitCode)."
        }
    }
}

Write-Host "Live ClamAV update and clean-scan verification passed."
