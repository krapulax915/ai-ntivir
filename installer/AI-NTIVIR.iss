; Inno Setup 6 script for AI-NTIVIR (AI Antivirus) - Windows 10/11
; NOTE: this Inno Setup 6.5 build wants "=" in [Setup] directives and
; "Param: Value" in the row-style sections ([Languages], [Files], ...).
; Build: ISCC.exe installer\AI-NTIVIR.iss
; Result: installer\output\AI-NTIVIR-Setup-<version>.exe

#define MyAppName "AI-NTIVIR"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Krapulix Soft"
#define MyAppURL "https://ai-ntivir.eu"

[Setup]
AppId=AI-NTIVIR-KRAPULIXSOFT-7A3E1C92-5F4B-4D6E-9B21-8C4D2E6F1A93
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\AI-NTIVIR
DefaultGroupName=AI-NTIVIR
LicenseFile=..\LICENSE
OutputDir=output
OutputBaseFilename=AI-NTIVIR-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\AI-NTIVIR.exe
Uninstallable=yes
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "hungarian"; MessagesFile: "compiler:Languages\Hungarian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; The complete PyInstaller output folder (AI-NTIVIR.exe + _internal + data)
; NOTE: PyInstaller writes to <repo root>\dist\AI-NTIVIR (relative to the spec).
Source: "..\dist\AI-NTIVIR\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\AI-NTIVIR"; Filename: "{app}\AI-NTIVIR.exe"
Name: "{group}\Uninstall AI-NTIVIR"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AI-NTIVIR"; Filename: "{app}\AI-NTIVIR.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AI-NTIVIR.exe"; Description: "Launch AI-NTIVIR"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Runtime logs/quarantine under ProgramData are intentionally kept on uninstall
Type: files; Name: "{app}\aintivirus_debug.log"
