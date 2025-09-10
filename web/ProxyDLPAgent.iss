; --------------------------------------------
; ProxyDLP Agent Installer Script (Silent + Logging)
; --------------------------------------------

#define ProxyHostname "placeholder"  ; default, overridden at compile-time

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

; Certificate
Source: "mitmCA.pem"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Registry]
Root: HKLM; Subkey: "Software\ProxyDLP"; ValueType: string; ValueName: "ProxyHostname"; ValueData: "{#ProxyHostname}"

[Run]
; Create a log directory if not exists
Filename: "cmd.exe"; Parameters: "/C if not exist ""{commonappdata}\ProxyDLPAgent"" mkdir ""{commonappdata}\ProxyDLPAgent"""; Flags: runhidden

; Install certificate silently with logging
Filename: "cmd.exe"; Parameters: "/C certutil.exe -addstore root ""{tmp}\mitmCA.pem"" >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden

; Register service (if not exists)
Filename: "cmd.exe"; Parameters: "/C sc query ProxyDLPAgent || sc create ProxyDLPAgent binPath= ""{app}\proxydlp.exe"" start= auto DisplayName= ""ProxyDLP Agent"" >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden

; Start service with logging
Filename: "cmd.exe"; Parameters: "/C sc start ProxyDLPAgent >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden

[Icons]
Name: "{group}\ProxyDLP Agent"; Filename: "{app}\proxydlp.exe"
Name: "{commondesktop}\ProxyDLP Agent"; Filename: "{app}\proxydlp.exe"

[UninstallRun]
; Stop and delete service during uninstall
Filename: "cmd.exe"; Parameters: "/C sc stop ProxyDLPAgent >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden
Filename: "cmd.exe"; Parameters: "/C sc delete ProxyDLPAgent >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden

; Optionally delete driver and files (if not in [Files] uninstall)
Filename: "cmd.exe"; Parameters: "/C del /F /Q ""{app}\WinDivert64.sys"" >> ""{commonappdata}\ProxyDLPAgent\install.log"" 2>&1"; Flags: runhidden
