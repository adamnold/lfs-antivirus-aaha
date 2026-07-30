#define AppName "Local-First Antivirus"
#define AppVersion "0.3.0-beta.1"
#define AppNumericVersion "0.3.0.1"
#define AppExeName "Local-First Antivirus.exe"
#define AppPublisher "Adam And His Agents (AAHA)"
#define AppUrl "https://github.com/adamnold/lfs-antivirus-aaha"

[Setup]
AppId={{2A3B04D3-AE65-538B-9583-D7CA496CBF6A}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/security
AppUpdatesURL={#AppUrl}/releases
DefaultDirName={localappdata}\Programs\AAHA\lfs-antivirus-aaha
DefaultGroupName=AAHA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir=..\dist\installer
OutputBaseFilename=Local-First-Antivirus-v0.3.0-beta.1-Windows-x64-Setup
SetupIconFile=..\assets\lfs-antivirus-aaha.ico
LicenseFile=..\LICENSE
InfoBeforeFile=INSTALLER_NOTICE.txt
VersionInfoVersion={#AppNumericVersion}
VersionInfoProductVersion={#AppNumericVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} per-user installer
VersionInfoProductName={#AppName}
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
ChangesAssociations=no

[InstallDelete]
Type: filesandordirs; Name: "{app}\lfs_antivirus_aaha"
Type: filesandordirs; Name: "{app}\definitions"
Type: filesandordirs; Name: "{app}\tests"
Type: files; Name: "{app}\run-lfs-antivirus-aaha.bat"
Type: files; Name: "{app}\run-lfs-antivirus-aaha.ps1"
Type: files; Name: "{app}\install-lfs-antivirus-aaha.ps1"

[Files]
Source: "..\dist\windows\Local-First Antivirus\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Local-First Antivirus"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall Local-First Antivirus"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch Local-First Antivirus"; Flags: nowait postinstall skipifsilent unchecked
