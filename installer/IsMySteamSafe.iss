#ifndef PayloadDir
  #error PayloadDir must be supplied.
#endif
#ifndef OutputDir
  #error OutputDir must be supplied.
#endif
#ifndef AppVersion
  #define AppVersion "0.2.6"
#endif

[Setup]
AppId={{7D915C98-B640-43B2-8C8B-6B14C42C52A0}
AppName=我的 Steam 安全吗？
AppVersion={#AppVersion}
AppPublisher=fenglinbei
AppPublisherURL=https://github.com/fenglinbei/IsMySteamSafe
AppSupportURL=https://github.com/fenglinbei/IsMySteamSafe/issues
DefaultDirName={localappdata}\Programs\IsMySteamSafe
DefaultGroupName=我的 Steam 安全吗？
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=IsMySteamSafe-{#AppVersion}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\IsMySteamSafe.exe
SetupIconFile={#PayloadDir}\Assets\App.ico
LicenseFile={#PayloadDir}\LICENSE
#ifdef EnableSigning
SignTool=fenglinbei
SignedUninstaller=yes
SignedUninstallerDir={#OutputDir}\signing-cache\IsMySteamSafe
#endif

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked

[Icons]
Name: "{autoprograms}\我的 Steam 安全吗？"; Filename: "{app}\IsMySteamSafe.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\我的 Steam 安全吗？"; Filename: "{app}\IsMySteamSafe.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\IsMySteamSafe.exe"; Description: "启动 我的 Steam 安全吗？"; Flags: nowait postinstall skipifsilent runasoriginaluser
