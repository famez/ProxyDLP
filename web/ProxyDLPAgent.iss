; --------------------------------------------
; ProxyDLP Agent Installer Script
; --------------------------------------------

#define ProxyHostname "127.0.0.1"  ; default, will override from .env

[Setup]
AppName=ProxyDLP Agent
AppVersion=1.0
DefaultDirName={pf}\ProxyDLPAgent
DefaultGroupName=ProxyDLP
UninstallDisplayIcon={app}\proxydlp.exe
Compression=lzma
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=ProxyDLPAgentSetup
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
; Main executable
Source: "proxydlp.exe"; DestDir: "{app}"; Flags: ignoreversion

; Supporting DLLs
Source: "libcurl-x64.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "libwinpthread-1.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion

; Certificate (to be imported later)
Source: "mitmCA.pem"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Registry]
; Example registry keys
Root: HKLM; Subkey: "Software\ProxyDLP"; ValueType: string; ValueName: "ProxyHostname"; ValueData: "{#ProxyHostname}"

[Run]
; Install certificate into ROOT store
Filename: "certutil.exe"; Parameters: "-addstore root ""{tmp}\mitmCA.pem"""; Flags: runhidden

; Register proxydlp.exe as a Windows service
Filename: "sc.exe"; Parameters: "create ProxyDLPAgent binPath= ""{app}\proxydlp.exe"" start= auto DisplayName= ""ProxyDLP Agent"""; Flags: runhidden

; Start the service immediately
Filename: "sc.exe"; Parameters: "start ProxyDLPAgent"; Flags: runhidden

; Run agent after install (optional)
; Filename: "{app}\proxydlp.exe"; Description: "Run ProxyDLP Agent"; Flags: nowait postinstall

[Icons]
Name: "{group}\ProxyDLP Agent"; Filename: "{app}\proxydlp.exe"
Name: "{commondesktop}\ProxyDLP Agent"; Filename: "{app}\proxydlp.exe"