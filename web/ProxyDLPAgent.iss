; --------------------------------------------
; ProxyDLP Agent Installer Script
; --------------------------------------------

#define ProxyHostname "placeholder"  ; default, overridden at compile-time
#define LogFile "{commonappdata}\ProxyDLPAgent\install.log"

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
SetupLogging=yes

[Dirs]
; Create the log directory so that install.log can be written
Name: "{commonappdata}\ProxyDLPAgent"

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
; Install certificate silently and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Installing mitmCA certificate... >> ""{#LogFile}"" & certutil.exe -addstore root ""{tmp}\mitmCA.pem"" >> ""{#LogFile}"" 2>&1 & if errorlevel 1 (echo [%DATE% %TIME%] ERROR: Certificate installation failed. >> ""{#LogFile}"") else (echo [%DATE% %TIME%] Certificate installed successfully. >> ""{#LogFile}"")"; Flags: runhidden

; Register service (if not exists) and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Registering ProxyDLPAgent service... >> ""{#LogFile}"" & (sc query ProxyDLPAgent >> ""{#LogFile}"" 2>&1 && echo [%DATE% %TIME%] Service already exists, skipping creation. >> ""{#LogFile}"") || (sc create ProxyDLPAgent binPath= ""{app}\proxydlp.exe"" start= auto DisplayName= ""ProxyDLP Agent"" >> ""{#LogFile}"" 2>&1 & if errorlevel 1 (echo [%DATE% %TIME%] ERROR: Service registration failed. >> ""{#LogFile}"") else (echo [%DATE% %TIME%] Service registered successfully. >> ""{#LogFile}""))"; Flags: runhidden

; Start service and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Starting ProxyDLPAgent service... >> ""{#LogFile}"" & sc start ProxyDLPAgent >> ""{#LogFile}"" 2>&1 & if errorlevel 1 (echo [%DATE% %TIME%] ERROR: Service failed to start. >> ""{#LogFile}"") else (echo [%DATE% %TIME%] Service started successfully. >> ""{#LogFile}"")"; Flags: runhidden


[UninstallRun]
; Stop ProxyDLPAgent, wait until stopped, and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Stopping ProxyDLPAgent service... >> ""{#LogFile}"" & sc stop ProxyDLPAgent >> ""{#LogFile}"" 2>&1 & :loop & sc query ProxyDLPAgent | findstr /I ""STOPPED"" >nul && (echo [%DATE% %TIME%] Service stopped successfully. >> ""{#LogFile}"") || (timeout /t 1 >nul & goto loop)"; Flags: runhidden

; Delete service and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Deleting ProxyDLPAgent service... >> ""{#LogFile}"" & sc delete ProxyDLPAgent >> ""{#LogFile}"" 2>&1 & if errorlevel 1 (echo [%DATE% %TIME%] ERROR: Service deletion failed. >> ""{#LogFile}"") else (echo [%DATE% %TIME%] Service deleted successfully. >> ""{#LogFile}"")"; Flags: runhidden

; Deregister executable and log result
Filename: "cmd.exe"; Parameters: "/C echo [%DATE% %TIME%] Deregistering ProxyDLP agent... >> ""{#LogFile}"" & ""{app}\proxydlp.exe"" /deregister >> ""{#LogFile}"" 2>&1 & if errorlevel 1 (echo [%DATE% %TIME%] ERROR: Agent deregistration failed. >> ""{#LogFile}"") else (echo [%DATE% %TIME%] Agent deregistered successfully. >> ""{#LogFile}"")"; Flags: runhidden

[Code]
{ ---- Pascal script: log session start/end with timestamps ---- }

var
  InstallSucceeded: Boolean;

procedure AppendLog(const Msg: String);
begin
  { Use the same path defined by the LogFile preprocessor constant above }
  SaveStringToFile(ExpandConstant('{#LogFile}'), Msg + #13#10, True);
end;

function InitializeSetup(): Boolean;
begin
  { Ensure the log directory exists before any log writes }
  ForceDirectories(ExpandConstant('{commonappdata}\ProxyDLPAgent'));
  InstallSucceeded := False;
  AppendLog('');
  AppendLog('============================================================');
  AppendLog('ProxyDLP Agent installation started');
  AppendLog('============================================================');
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssDone then
    InstallSucceeded := True;
end;

procedure DeinitializeSetup();
begin
  if InstallSucceeded then
    AppendLog('Installation completed successfully.')
  else
    AppendLog('Installation did not complete (cancelled or error — check entries above).');
  AppendLog('============================================================');
  AppendLog('');
end;

procedure InitializeUninstallProgressForm();
begin
  AppendLog('');
  AppendLog('============================================================');
  AppendLog('ProxyDLP Agent uninstallation started');
  AppendLog('============================================================');
end;

procedure DeinitializeUninstall();
begin
  AppendLog('Uninstallation finished.');
  AppendLog('============================================================');
  AppendLog('');
end;

