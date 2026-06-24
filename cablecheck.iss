; cablecheck Inno Setup script
; Requires Inno Setup 6+ — https://jrsoftware.org/isdl.php
; Build with: ISCC cablecheck.iss
; Or open in Inno Setup IDE and press Compile

#define AppName "cablecheck"
#define AppVersion "1.0.0"
#define AppPublisher "AMIT"
#define AppURL "https://github.com/Bryson-he/cablecheck"
#define AppExeName "cablecheck.exe"
#define NpcapURL "https://npcap.com/dist/npcap-1.79.exe"

[Setup]
AppId={{A3F2C1D4-8B7E-4F2A-9C3D-1E5F6A7B8C9D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=no
OutputDir=installer_output
OutputBaseFilename=cablecheck_setup
SetupIconFile=cablecheck.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=no
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=Dual-NIC loopback cable tester
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; Main application
Source: "install\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Npcap installer — bundled so install works offline
; Download npcap-1.79.exe from https://npcap.com and place it next to this .iss file
Source: "npcap-1.79.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NpcapNotInstalled

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; IconFilename: "{app}\{#AppExeName}"

[Run]
; Install Npcap silently if not already present
Filename: "{tmp}\npcap-1.79.exe"; Parameters: "/S /winpcap_mode=yes"; \
  StatusMsg: "Installing Npcap (required for packet capture)..."; \
  Flags: waituntilterminated; Check: NpcapNotInstalled

; Launch after install
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; \
  Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Nothing extra needed — Npcap has its own uninstaller in Add/Remove Programs

[Code]
function NpcapNotInstalled: Boolean;
begin
  Result := not (
    RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
    FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'))
  );
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'This will install cablecheck ' + '{#AppVersion}' + ' on your computer.' + #13#10 + #13#10 +
    'cablecheck is a dual-NIC loopback cable tester. Plug both ends of a CAT cable ' +
    'into this PC and test for continuity, packet loss, and link quality.' + #13#10 + #13#10 +
    'Npcap will be installed automatically if not already present.' + #13#10 + #13#10 +
    'Click Next to continue.';
end;
