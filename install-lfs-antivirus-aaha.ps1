$ErrorActionPreference = "Stop"

$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = Join-Path $env:LOCALAPPDATA "Programs\AAHA\lfs-antivirus-aaha"
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $startMenu "Local-First Antivirus.lnk"

New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $installRoot -Recurse -Force

$launcher = Join-Path $installRoot "run-lfs-antivirus-aaha.bat"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcher
$shortcut.WorkingDirectory = $installRoot
$shortcut.Description = "Local-First Antivirus - AAHA Local-First Series"
$shortcut.Save()

Write-Host "Installed Local-First Antivirus from Adam And His Agents (AAHA)."
Write-Host "Start Menu shortcut: $shortcutPath"
Write-Host "Install folder: $installRoot"
