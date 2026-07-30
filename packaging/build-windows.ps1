[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$InnoCompiler = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$expectedVersion = "0.3.0-beta.1"
$expectedPyInstaller = "6.21.0"
$appName = "Local-First Antivirus"
$appExeName = "$appName.exe"
$buildRoot = Join-Path $repoRoot "build\pyinstaller"
$windowsRoot = Join-Path $repoRoot "dist\windows"
$installerRoot = Join-Path $repoRoot "dist\installer"
$releaseRoot = Join-Path $repoRoot "dist\release"
$evidenceRoot = Join-Path $repoRoot "dist\evidence"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

$actualVersion = (& $Python -c "from lfs_antivirus_aaha import __version__; print(__version__)").Trim()
if ($LASTEXITCODE -ne 0 -or $actualVersion -ne $expectedVersion) {
    throw "Expected application version $expectedVersion; received $actualVersion."
}

$actualPyInstaller = (& $Python -m PyInstaller --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualPyInstaller -ne $expectedPyInstaller) {
    throw "Expected PyInstaller $expectedPyInstaller; received $actualPyInstaller."
}

$sourceCommit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw "A full source commit is required for package provenance."
}

foreach ($generatedPath in @($buildRoot, $windowsRoot, $installerRoot, $releaseRoot, $evidenceRoot)) {
    if (Test-Path -LiteralPath $generatedPath) {
        Remove-Item -LiteralPath $generatedPath -Recurse -Force
    }
}

New-Item -ItemType Directory -Path $buildRoot, $windowsRoot, $installerRoot, $releaseRoot, $evidenceRoot -Force | Out-Null

$pyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--windowed",
    "--name", $appName,
    "--icon", (Join-Path $repoRoot "assets\lfs-antivirus-aaha.ico"),
    "--version-file", (Join-Path $repoRoot "packaging\windows-version-info.txt"),
    "--distpath", $windowsRoot,
    "--workpath", (Join-Path $buildRoot "work"),
    "--specpath", (Join-Path $buildRoot "spec"),
    (Join-Path $repoRoot "lfs_antivirus_aaha\app.py")
)
Invoke-Checked -FilePath $Python -Arguments $pyInstallerArgs

$bundleRoot = Join-Path $windowsRoot $appName
$appExe = Join-Path $bundleRoot $appExeName
if (-not (Test-Path -LiteralPath $appExe -PathType Leaf)) {
    throw "PyInstaller did not produce $appExe."
}

$licenseRoot = Join-Path $bundleRoot "licenses"
New-Item -ItemType Directory -Path $licenseRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $licenseRoot "AAHA-MIT.txt")
Copy-Item -LiteralPath (Join-Path $repoRoot "NOTICE.md") -Destination (Join-Path $bundleRoot "NOTICE.md")
Copy-Item -LiteralPath (Join-Path $repoRoot "PRIVACY.md") -Destination (Join-Path $bundleRoot "PRIVACY.md")
Copy-Item -LiteralPath (Join-Path $repoRoot "SECURITY.md") -Destination (Join-Path $bundleRoot "SECURITY.md")
Copy-Item -LiteralPath (Join-Path $repoRoot "packaging\THIRD_PARTY_NOTICES.md") -Destination (Join-Path $bundleRoot "THIRD_PARTY_NOTICES.md")

$pythonRoot = (& $Python -c "import pathlib, sys; print(pathlib.Path(sys.base_prefix).resolve())").Trim()
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonRoot -PathType Container)) {
    throw "Could not resolve the Python runtime root."
}
$pythonLicense = Join-Path $pythonRoot "LICENSE.txt"
if (-not (Test-Path -LiteralPath $pythonLicense -PathType Leaf)) {
    throw "The Python runtime license was not found at $pythonLicense."
}
Copy-Item -LiteralPath $pythonLicense -Destination (Join-Path $licenseRoot "Python-LICENSE.txt")

$tkLicense = Get-ChildItem -LiteralPath $pythonRoot -Filter "license.terms" -File -Recurse |
    Where-Object { $_.FullName -match '[\\/]tcl[\\/]' } |
    Select-Object -First 1
if ($null -eq $tkLicense) {
    throw "The bundled Tcl/Tk license.terms file was not found under $pythonRoot."
}
Copy-Item -LiteralPath $tkLicense.FullName -Destination (Join-Path $licenseRoot "Tcl-Tk-license.terms")

$buildInfo = [ordered]@{
    app_name = $appName
    app_version = $expectedVersion
    architecture = "windows-x64"
    source_commit = $sourceCommit
    python_version = (& $Python --version).Trim()
    pyinstaller_version = $actualPyInstaller
    clamav_bundled = $false
}
$buildInfoJson = $buildInfo | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText(
    (Join-Path $bundleRoot "BUILD_INFO.json"),
    $buildInfoJson + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

if (-not $InnoCompiler) {
    $innoCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe")
    )
    $InnoCompiler = $innoCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
}
if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw "Inno Setup 7 ISCC.exe was not found."
}

Invoke-Checked -FilePath $InnoCompiler -Arguments @((Join-Path $repoRoot "packaging\lfs-antivirus-aaha.iss"))

$installers = @(Get-ChildItem -LiteralPath $installerRoot -Filter "*.exe" -File)
if ($installers.Count -ne 1) {
    throw "Expected exactly one installer; found $($installers.Count)."
}
$releaseInstaller = Join-Path $releaseRoot $installers[0].Name
Copy-Item -LiteralPath $installers[0].FullName -Destination $releaseInstaller
$installerHash = (Get-FileHash -LiteralPath $releaseInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumLine = "$installerHash  $($installers[0].Name)`n"
[System.IO.File]::WriteAllText(
    (Join-Path $releaseRoot "SHA256SUMS"),
    $checksumLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Built $releaseInstaller from $sourceCommit"
