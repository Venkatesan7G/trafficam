; Inno Setup script for the trafficam Windows installer.
; The release workflow builds it with:
;   iscc /DAppVersion=0.1.0 /DSourceDir=dist packaging\windows\trafficam.iss
; and the result is dist\trafficam-<version>-windows-amd64-setup.exe.
;
; What the installer does:
;   1. Copies trafficam.exe to C:\Program Files\trafficam.
;   2. Registers the "trafficam" Windows service (trafficam.exe service install)
;      and starts it. Its data and log live in C:\ProgramData\trafficam.
;   3. Creates empty watch and ignore lists there, unless you already have them.
; Uninstalling stops and removes the service. Your encrypted database in
; C:\ProgramData\trafficam is kept unless you tick the box to delete it.

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist"
#endif

[Setup]
; A fixed id so upgrades replace the old version instead of installing twice.
AppId={{6F3D1E52-8C4B-4E5A-9B0F-2A7C9D41E8B3}
AppName=trafficam
AppVersion={#AppVersion}
AppPublisher=trafficam contributors
AppPublisherURL=https://github.com/Venkatesan7G/trafficam
AppSupportURL=https://github.com/Venkatesan7G/trafficam/issues
DefaultDirName={autopf}\trafficam
DisableProgramGroupPage=yes
DisableDirPage=yes
LicenseFile=..\..\LICENSE
OutputDir={#SourceDir}
OutputBaseFilename=trafficam-{#AppVersion}-windows-amd64-setup
; Installing a service needs administrator rights.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 or newer.
MinVersion=10.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\trafficam.exe
SetupLogging=yes

[Files]
Source: "{#SourceDir}\trafficam.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"
Source: "..\..\README.md"; DestDir: "{app}"
Source: "..\..\docs\WINDOWS.md"; DestDir: "{app}"
; Your lists: only copied if missing, and never deleted on uninstall.
Source: "..\lists\watch.txt"; DestDir: "{commonappdata}\trafficam"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "..\lists\ignore.txt"; DestDir: "{commonappdata}\trafficam"; Flags: onlyifdoesntexist uninsneveruninstall

[Run]
Filename: "{app}\trafficam.exe"; \
  Parameters: "service install -watch ""{commonappdata}\trafficam\watch.txt"" -ignore ""{commonappdata}\trafficam\ignore.txt"""; \
  StatusMsg: "Registering the trafficam service..."; Flags: runhidden waituntilterminated
Filename: "{app}\trafficam.exe"; Parameters: "service start"; \
  StatusMsg: "Starting the trafficam service..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\trafficam.exe"; Parameters: "service uninstall"; \
  RunOnceId: "RemoveService"; Flags: runhidden waituntilterminated

[Code]
const
  ServiceName = 'trafficam';

// Stops the service and waits (up to 30 s) until Windows reports it stopped,
// so its .exe file is no longer locked.
procedure StopServiceAndWait();
var
  ResultCode, I: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  for I := 1 to 30 do
  begin
    // "sc query" exit code is 0 while the service exists; we look for STOPPED
    // by asking PowerShell, which gives a clean yes/no exit code.
    Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -Command "if ((Get-Service ' + ServiceName + ' -ErrorAction SilentlyContinue).Status -eq ''Running'') { exit 1 } else { exit 0 }"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if ResultCode = 0 then
      Exit;
    Sleep(1000);
  end;
end;

// Before copying files: on an upgrade, stop and unregister the old service.
// [Run] above registers it again with the new .exe.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  OldExe: String;
begin
  Result := '';
  OldExe := ExpandConstant('{app}\trafficam.exe');
  if FileExists(OldExe) then
  begin
    StopServiceAndWait();
    Exec(OldExe, 'service uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

// Before uninstalling: stop the service so its .exe can be deleted.
function InitializeUninstall(): Boolean;
begin
  StopServiceAndWait();
  Result := True;
end;

// After uninstalling: offer to delete the data folder (database, key, log).
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\trafficam');
    if DirExists(DataDir) and not UninstallSilent() then
      if MsgBox('Also delete trafficam''s data in ' + DataDir + '?' + #13#10 + #13#10 +
                'This removes the encrypted database, its key, your watch and ignore lists, and the log. ' +
                'Keep it if you plan to reinstall and want trafficam to remember what it has learned.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
