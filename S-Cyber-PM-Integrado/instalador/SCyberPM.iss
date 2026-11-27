; Instalador do S-Cyber PM (Inno Setup 6) - gerado no CI (windows-latest).
; Instala POR USUÁRIO, sem pedir administrador: %LOCALAPPDATA%\Programs\S-Cyber PM.
; Os dados do usuário (%APPDATA%\SCyberPM) e a ativação (%LOCALAPPDATA%\SCyberPM) NÃO são
; apagados na desinstalação nem na atualização.
#ifndef AppVersion
  #define AppVersion "2.0.5"
#endif

[Setup]
AppId={{6F2B8E5C-3D4A-4B7E-9C1F-5A8D2E7B4C90}
AppName=S-Cyber
AppVersion={#AppVersion}
AppVerName=S-Cyber {#AppVersion}
AppPublisher=Equipe S-Cyber
AppCopyright=Copyright (c) 2026 Leonídio Alves de Moraes Junior, Daniel Otavio de Lima Medrado e Gabriel Silveira Lima
AppContact=scybersuporte@gmail.com
DefaultDirName={autopf}\S-Cyber PM
DefaultGroupName=S-Cyber
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
; Termos de Uso: o instalador só continua se a pessoa aceitar. Política de privacidade antes da instalação.
LicenseFile=..\legal\TERMOS_DE_USO.txt
InfoBeforeFile=..\legal\POLITICA_DE_PRIVACIDADE.txt

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Atalhos:"

[Files]
Source: "..\dist\SCyberPM.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\legal\*.txt"; DestDir: "{app}\legal"; Flags: ignoreversion

[Icons]
Name: "{group}\S-Cyber"; Filename: "{app}\SCyberPM.exe"
Name: "{group}\S-Cyber - painel NIST"; Filename: "{app}\SCyberPM.exe"; Parameters: "--nist"
Name: "{group}\S-Cyber - diagnóstico de abertura"; Filename: "{app}\SCyberPM.exe"; Parameters: "--diagnostico"
Name: "{group}\Termos de Uso e Privacidade"; Filename: "{app}\legal"
Name: "{autodesktop}\S-Cyber"; Filename: "{app}\SCyberPM.exe"; Tasks: desktopicon

[InstallDelete]
; Atalhos com o nome antigo (até a 2.0.5): o nome do produto agora é neutro (PM ou Business).
Type: files; Name: "{group}\S-Cyber PM.lnk"
Type: files; Name: "{group}\S-Cyber PM - painel NIST.lnk"
Type: files; Name: "{group}\S-Cyber PM - diagnóstico de abertura.lnk"
Type: files; Name: "{autodesktop}\S-Cyber PM.lnk"

[Run]
Filename: "{app}\SCyberPM.exe"; Description: "Abrir o S-Cyber"; Flags: nowait postinstall skipifsilent
