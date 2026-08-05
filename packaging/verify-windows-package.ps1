[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$version = "0.4.0-beta.1"
$appName = "Local-First Antivirus"
$appExeName = "$appName.exe"
$bundleRoot = Join-Path $repoRoot "dist\windows\$appName"
$bundleExe = Join-Path $bundleRoot $appExeName
$releaseRoot = Join-Path $repoRoot "dist\release"
$evidenceRoot = Join-Path $repoRoot "dist\evidence"
$installer = @(Get-ChildItem -LiteralPath $releaseRoot -Filter "*.exe" -File)
if ($installer.Count -ne 1) {
    throw "Expected one release installer; found $($installer.Count)."
}
if (-not (Test-Path -LiteralPath $bundleExe -PathType Leaf)) {
    throw "Packaged executable is missing: $bundleExe"
}

$fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($bundleExe)
if ($fileInfo.ProductName -ne $appName) {
    throw "Unexpected ProductName: $($fileInfo.ProductName)"
}
if ($fileInfo.ProductVersion -ne $version -or $fileInfo.FileVersion -ne $version) {
    throw "Unexpected executable version metadata: $($fileInfo.FileVersion) / $($fileInfo.ProductVersion)"
}
if ($fileInfo.CompanyName -ne "Technology Biased LLC") {
    throw "Unexpected CompanyName: $($fileInfo.CompanyName)"
}

$sourcePayload = @(Get-ChildItem -LiteralPath $bundleRoot -File -Recurse | Where-Object { $_.Extension -in @('.py', '.pyc', '.pyo') })
if ($sourcePayload.Count -ne 0) {
    throw "The package contains Python source or bytecode files."
}
$bundledClamAv = @(Get-ChildItem -LiteralPath $bundleRoot -File -Recurse | Where-Object { $_.Name -in @('clamscan.exe', 'freshclam.exe') })
if ($bundledClamAv.Count -ne 0) {
    throw "ClamAV must remain an external dependency and was unexpectedly bundled."
}

$appSignature = Get-AuthenticodeSignature -LiteralPath $bundleExe
$installerSignature = Get-AuthenticodeSignature -LiteralPath $installer[0].FullName
foreach ($signature in @($appSignature, $installerSignature)) {
    if ($signature.Status -notin @('NotSigned', 'Valid')) {
        throw "Unexpected Authenticode status: $($signature.Status)"
    }
}
if ($appSignature.Status -ne 'NotSigned' -or $installerSignature.Status -ne 'NotSigned') {
    throw "This beta is expected to be unsigned until Technology Biased LLC provisions Artifact Signing."
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class AahaWindowCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint flags);
}
"@

function Save-WindowScreenshot {
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Handle,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rect = New-Object AahaWindowCapture+RECT
    if (-not [AahaWindowCapture]::GetWindowRect($Handle, [ref]$rect)) {
        throw "GetWindowRect failed."
    }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 900 -or $height -lt 600) {
        throw "The application window was unexpectedly small: ${width}x${height}."
    }
    $bitmap = New-Object System.Drawing.Bitmap($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $hdc = $graphics.GetHdc()
        try {
            $captured = [AahaWindowCapture]::PrintWindow($Handle, $hdc, 2)
        }
        finally {
            $graphics.ReleaseHdc($hdc)
        }
        if (-not $captured) {
            $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

$verificationRoot = Join-Path ([System.IO.Path]::GetTempPath()) "aaha-antivirus-package-verification"
$installRoot = Join-Path $verificationRoot "installed app"
$stateRoot = Join-Path $verificationRoot "state"
$canonicalSentinel = Join-Path $stateRoot "AAHA\lfs-antivirus-aaha\state-preservation-sentinel.txt"
$legacySentinel = Join-Path $stateRoot "LocalShieldAV\legacy-state-preservation-sentinel.txt"
$installLog = Join-Path $evidenceRoot "install.log"
$upgradeLog = Join-Path $evidenceRoot "upgrade.log"
$uninstallLog = Join-Path $evidenceRoot "uninstall.log"
$screenshot = Join-Path $evidenceRoot "installed-ui.png"
$oldLocalAppData = $env:LOCALAPPDATA
$launchedProcess = $null

if (Test-Path -LiteralPath $verificationRoot) {
    Remove-Item -LiteralPath $verificationRoot -Recurse -Force
}
New-Item -ItemType Directory -Path (Split-Path $canonicalSentinel), (Split-Path $legacySentinel), $evidenceRoot -Force | Out-Null
[System.IO.File]::WriteAllText($canonicalSentinel, "canonical-state-must-survive`n", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($legacySentinel, "legacy-state-must-survive`n", [System.Text.UTF8Encoding]::new($false))
$canonicalBefore = (Get-FileHash -LiteralPath $canonicalSentinel -Algorithm SHA256).Hash
$legacyBefore = (Get-FileHash -LiteralPath $legacySentinel -Algorithm SHA256).Hash
$env:LOCALAPPDATA = $stateRoot

try {
    foreach ($installPass in @(
        @{ Log = $installLog; Label = "install" },
        @{ Log = $upgradeLog; Label = "same-version upgrade" }
    )) {
        $arguments = @(
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/DIR=`"$installRoot`"",
            "/LOG=`"$($installPass.Log)`""
        )
        $process = Start-Process -FilePath $installer[0].FullName -ArgumentList $arguments -PassThru -Wait
        if ($process.ExitCode -ne 0) {
            throw "The $($installPass.Label) pass failed with exit code $($process.ExitCode)."
        }
        if (-not (Test-Path -LiteralPath (Join-Path $installRoot $appExeName) -PathType Leaf)) {
            throw "The application executable is missing after $($installPass.Label)."
        }
    }

    $installedExe = Join-Path $installRoot $appExeName
    $launchedProcess = Start-Process -FilePath $installedExe -WorkingDirectory $installRoot -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 250
        $launchedProcess.Refresh()
        if ($launchedProcess.HasExited) {
            throw "The installed application exited before presenting its main window (exit $($launchedProcess.ExitCode))."
        }
    } while ($launchedProcess.MainWindowHandle -eq [IntPtr]::Zero -and [DateTime]::UtcNow -lt $deadline)

    if ($launchedProcess.MainWindowHandle -eq [IntPtr]::Zero) {
        throw "The installed application did not present a main window within 45 seconds."
    }
    if ($launchedProcess.MainWindowTitle -notlike "Local-First Antivirus*") {
        throw "Unexpected main-window title: $($launchedProcess.MainWindowTitle)"
    }
    Save-WindowScreenshot -Handle $launchedProcess.MainWindowHandle -Path $screenshot
    if (-not $launchedProcess.CloseMainWindow()) {
        throw "The installed application's main window did not accept a close request."
    }
    if (-not $launchedProcess.WaitForExit(15000)) {
        throw "The installed application did not exit cleanly within 15 seconds."
    }
    if ($launchedProcess.ExitCode -ne 0) {
        throw "The installed application exited with code $($launchedProcess.ExitCode)."
    }
    $launchedProcess = $null

    $uninstaller = Join-Path $installRoot "unins000.exe"
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw "The uninstaller was not installed."
    }
    $uninstallArguments = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/LOG=`"$uninstallLog`""
    )
    $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList $uninstallArguments -PassThru -Wait
    if ($uninstallProcess.ExitCode -ne 0) {
        throw "Uninstall failed with exit code $($uninstallProcess.ExitCode)."
    }
    Start-Sleep -Seconds 2
    if (Test-Path -LiteralPath $installedExe -PathType Leaf) {
        throw "The executable remains after uninstall."
    }

    $shortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\AAHA\Local-First Antivirus.lnk"
    if (Test-Path -LiteralPath $shortcut) {
        throw "The Start Menu shortcut remains after uninstall."
    }
    if ((Get-FileHash -LiteralPath $canonicalSentinel -Algorithm SHA256).Hash -ne $canonicalBefore) {
        throw "Canonical application state changed during install/upgrade/remove verification."
    }
    if ((Get-FileHash -LiteralPath $legacySentinel -Algorithm SHA256).Hash -ne $legacyBefore) {
        throw "Legacy application state changed during install/upgrade/remove verification."
    }

    $sourceCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
    $evidence = [ordered]@{
        schema_version = 1
        app_name = $appName
        app_version = $version
        source_commit = $sourceCommit
        installer_file = $installer[0].Name
        installer_sha256 = (Get-FileHash -LiteralPath $installer[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        executable_metadata_verified = $true
        python_source_absent = $true
        clamav_not_bundled = $true
        app_signature_status = $appSignature.Status.ToString()
        installer_signature_status = $installerSignature.Status.ToString()
        install_verified = $true
        same_version_upgrade_verified = $true
        ui_launch_and_clean_exit_verified = $true
        uninstall_verified = $true
        canonical_state_preserved = $true
        legacy_state_preserved = $true
        screenshot_file = (Split-Path $screenshot -Leaf)
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $evidenceRoot "release-evidence.json"),
        ($evidence | ConvertTo-Json -Depth 3) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
finally {
    if ($null -ne $launchedProcess -and -not $launchedProcess.HasExited) {
        Stop-Process -Id $launchedProcess.Id -Force -ErrorAction SilentlyContinue
    }
    $env:LOCALAPPDATA = $oldLocalAppData
}

Write-Host "Windows package lifecycle verification passed."
