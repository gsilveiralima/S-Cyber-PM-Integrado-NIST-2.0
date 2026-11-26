; Instalador do S-Cyber PM (Inno Setup 6) - gerado no CI (windows-latest).
; Instala POR USUÁRIO, sem pedir administrador: %LOCALAPPDATA%\Programs\S-Cyber PM.
; Os dados do usuário (%APPDATA%\SCyberPM) e a ativação (%LOCALAPPDATA%\SCyberPM) NÃO são
; apagados na desinstalação nem na atualização.
#ifndef AppVersion
  #define AppVersion "2.0.5"
#endif

[Setup]
AppId={{6F2B8E5C-3D4A-4B7E-9C1F-5A8D2E7B4C90}
AppName=S-Cyber PM
AppVersion={#AppVersion}
AppVerName=S-Cyber PM {#AppVersion}
AppPublisher=Polícia Militar do Estado de Goiás
DefaultDirName={autopf}\S-Cyber PM
DefaultGroupName=S-Cyber PM
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=SCyberPM-Setup-{#AppVersion}
SetupIconFile=..\build_exe\scyber_pm.ico
UninstallDisplayIcon={app}\SCyberPM.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Atalhos:"

[Files]
Source: "..\dist\SCyberPM.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\S-Cyber PM"; Filename: "{app}\SCyberPM.exe"
Name: "{group}\S-Cyber PM - painel NIST"; Filename: "{app}\SCyberPM.exe"; Parameters: "--nist"
Name: "{group}\S-Cyber PM - diagnóstico de abertura"; Filename: "{app}\SCyberPM.exe"; Parameters: "--diagnostico"
Name: "{autodesktop}\S-Cyber PM"; Filename: "{app}\SCyberPM.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SCyberPM.exe"; Description: "Abrir o S-Cyber PM"; Flags: nowait postinstall skipifsilent
