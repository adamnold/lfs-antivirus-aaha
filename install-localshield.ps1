$ErrorActionPreference = "Stop"

$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = Join-Path $env:LOCALAPPDATA "Programs\LocalShieldAV"
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $startMenu "LocalShield AV.lnk"

New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $installRoot -Recurse -Force

$launcher = Join-Path $installRoot "run-localshield.bat"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcher
$shortcut.WorkingDirectory = $installRoot
$shortcut.Description = "LocalShield AV"
$shortcut.Save()

Write-Host "Installed LocalShield AV for the current user."
Write-Host "Start Menu shortcut: $shortcutPath"
Write-Host "Install folder: $installRoot"
