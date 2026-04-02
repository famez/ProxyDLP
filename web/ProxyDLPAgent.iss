; --------------------------------------------
; ProxyDLP Agent Installer Script (Silent, No Logging)
; --------------------------------------------

#define ProxyHostname "placeholder"  ; default, overridden at compile-time

[Setup]
AppName=ProxyDLP Agent
AppVersion=1.0
DefaultDirName={pf}\ProxyDLPAgent
DefaultGroupName=ProxyDLP
UninstallDisplayIcon={app}\proxydlp.exe
DisableDirPage=yes
Compression=lzma
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=ProxyDLPAgentSetup
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
; Main executable
Source: "proxydlp.exe"; DestDir: "{app}"; Flags: ignoreversion

; Certificate (must be installed in Windows certificate storage for TLS interception)
Source: "mitmCA.pem"; DestDir: "{app}"; Flags: ignoreversion
Source: "mitmCA.pem"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Registry]
Root: HKLM; Subkey: "Software\ProxyDLP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\ProxyDLP"; ValueType: string; ValueName: "ProxyHostname"; ValueData: "{#ProxyHostname}"

[Run]
; Install certificate silently
Filename: "cmd.exe"; Parameters: "/C certutil.exe -addstore root ""{tmp}\mitmCA.pem"""; Flags: runhidden

; Register service (if not exists)
Filename: "cmd.exe"; Parameters: "/C sc query ProxyDLPAgent || sc create ProxyDLPAgent binPath= ""{app}\proxydlp.exe"" start= auto DisplayName= ""ProxyDLP Agent"""; Flags: runhidden

; Start service
Filename: "cmd.exe"; Parameters: "/C sc start ProxyDLPAgent"; Flags: runhidden


[UninstallRun]
; Stop ProxyDLPAgent and wait until stopped
Filename: "cmd.exe"; Parameters: "/C sc stop ProxyDLPAgent && :loop & sc query ProxyDLPAgent | findstr /I ""STOPPED"" >nul || (timeout /t 1 >nul & goto loop)"; Flags: runhidden

; Delete service
Filename: "cmd.exe"; Parameters: "/C sc delete ProxyDLPAgent"; Flags: runhidden

; Deregister executable
Filename: "cmd.exe"; Parameters: "/C ""{app}\proxydlp.exe"" /deregister"; Flags: runhidden

