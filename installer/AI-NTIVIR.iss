; Inno Setup 6 script for AI-NTIVIR (AI Antivirus) - Windows 10/11
; NOTE: this Inno Setup 6.5 build wants "=" in [Setup] directives and
; "Param: Value" in the row-style sections ([Languages], [Files], ...).
; Build: ISCC.exe installer\AI-NTIVIR.iss
; Result: installer\output\AI-NTIVIR-Setup-<version>.exe

#define MyAppName "AI-NTIVIR"
#define MyAppVersion "1.0.2"
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
Name: "autostart"; Description: "Start AI-NTIVIR automatically when Windows starts (system tray)"; GroupDescription: "Startup:"; Flags: checkedonce

[Registry]
; Autostart at user logon. The app starts hidden in the system tray.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AI-NTIVIR"; ValueData: """{app}\AI-NTIVIR.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Files]
; The complete PyInstaller output folder (AI-NTIVIR.exe + _internal + data)
; NOTE: PyInstaller writes to <repo root>\dist\AI-NTIVIR (relative to the spec).
Source: "..\dist\AI-NTIVIR\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

; The signature database is NOT inside the installer (keeps it small):
; it is downloaded from the official mirror during installation into the
; PyInstaller _internal bundle, where the frozen app resolves its data files.
; sha256: 9e890c7177d5ccf307c3d3e4f410bc20b51cd10ad8651f33c951b3ca6b54de4b
Source: "https://files.catbox.moe/lkjqct.db"; DestDir: "{app}\_internal\signatures"; DestName: "signatures.db"; ExternalSize: 188567552; Flags: download external ignoreversion

[Icons]
Name: "{group}\AI-NTIVIR"; Filename: "{app}\AI-NTIVIR.exe"
Name: "{group}\Uninstall AI-NTIVIR"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AI-NTIVIR"; Filename: "{app}\AI-NTIVIR.exe"; Tasks: desktopicon

[Run]
; Launch with the dashboard visible after installation (without --show-gui the
; app starts hidden in the system tray and the user sees nothing).
Filename: "{app}\AI-NTIVIR.exe"; Parameters: "--show-gui"; Description: "Launch AI-NTIVIR"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Runtime logs/quarantine under ProgramData are intentionally kept on uninstall
Type: files; Name: "{app}\aintivirus_debug.log"
