unit SDCommon;

interface

uses
  Windows;

const
  SecureDisplayServiceName = 'SDSecureDisplayService';
  SecureViewerProcessGroupBaseName = 'AAA-SecureViewer';
  SecureViewerDesktopName = 'AAA-SecureDesktop';
  SecureViewerMailslotForBackgroundService = 'AAA-SecureDesktop-Backgroundservice';
  SecureViewerMailslotForUserSessionManager = 'AAA-SecureDesktop-UserSessionManager';

  ApplicationDirectoryName = 'SecureDesktop';
  ConfigFileName = 'SecureDesktop.ini';
  INISection_Applications = 'Applications';
  INISection_Executables = 'Executables';
  INISection_CommandLines = 'CommandLines';
  INISection_ServiceRequest = 'ServiceRequest';
  INIIdent_RequestURL = 'RequestURL';
  INIIdent_RequestPort = 'RequestPort';
  BackgroundBitmapFileName = 'Background.bmp';

const
  SECURITY_WORLD_SID_AUTHORITY: Windows.TSidIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 1));
  SECURITY_LOCAL_SID_AUTHORITY: Windows.TSidIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 2));
  SECURITY_NT_AUTHORITY: Windows.TSidIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_WORLD_RID = ($00000000);
  SECURITY_LOCAL_SYSTEM_RID = 18;

type
  TSDLogVerbosity = (lvSilent, lvDetailed);

procedure Log(const AMessage: string);

function SDServiceRequestURL: string;
function SDServiceRequestPort: Cardinal;

function SDCreateSecureMailslot(const AMailslotName: string; out AMailslot: THandle): Boolean;
function SDOpenMailslot(const AMailslotName: string; out AMailslot: THandle): Boolean;
function SDWriteToMailslot(const AMailslot: THandle; const AMessage: string): Boolean;
function SDReadFromMailslot(const AMailslot: THandle; out AMessage: string): Boolean; overload;
function SDReadFromMailslot(const AMailslot: THandle; out AMessage: string;
  const ATimeout: Cardinal): Boolean; overload;
function SDIsMailslotEmpty(const AMailslot: THandle): Boolean;

function SDAppInfoLogoFileName(const nApplicationKey: Integer): string;
function SDAppInfoFullLogoFileName(const nApplicationKey: Integer): string;
function SDAppInfoBackgroundBitmapFileName: string;
function SDAppInfoApplicationName(const nApplicationKey: Integer): string;
function SDAppInfoApplicationExecutable(const nApplicationKey: Integer): string;
function SDAppInfoApplicationCommandLine(const nApplicationKey: Integer): string;

implementation

uses
  DateUtils,
  IniFiles,
  SysUtils,
  ShlObj,
  ActiveX,
  KnownFolders,
  AccCtrl,
  AclApi;

const
  SDLogFileName = 'C:\Projects\WinStaTest\SDLogFile-';
  SDLogFileNameExt = '.txt';

var
  FSDLogFileName: string;

procedure Log(const AMessage: string);
var
  DebugLog: TextFile;
begin
  AssignFile(DebugLog, FSDLogFileName);
  try
    Append(DebugLog);
  except
    Rewrite(DebugLog);
  end;
  Writeln(DebugLog, Format('%sT%s %s', [FormatDateTime('yyyymmdd', Now), FormatDateTime('hhnnss',
    Now), AMessage]));
  Flush(DebugLog);
  CloseFile(DebugLog);
end;

function ConfigDirectory: string;
var
  pszAppDataPath: PChar;
  nResult: Integer;
begin
  //Log('ConfigDirectory()');
  nResult := SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_CREATE, 0, pszAppDataPath);
  if Succeeded(nResult) then
  begin
    //Log('  Succeeded()');
    //Log(StrPas(pszAppDataPath));
    Result := Format('%s\%s', [StrPas(pszAppDataPath), ApplicationDirectoryName]);
    CoTaskMemFree(pszAppDataPath);
  end
  else
  begin
    Log(Format('  SHGetKnownFolderPath() failed: %d', [nResult]));
    Log(Format('  E_FAIL: %d', [E_FAIL]));
    Log(Format('  E_INVALIDARG: %d', [E_INVALIDARG]));
    Log(Format('  %s', [SysErrorMessage(GetLastError)]));
    GetMem(pszAppDataPath, 2048);
    StrPCopy(pszAppDataPath, 'C:\Users\hannol\AppData\Roaming');
    Result := Format('%s\%s', [StrPas(pszAppDataPath), ApplicationDirectoryName]);
    FreeMem(pszAppDataPath);
  end;
  //Log(Format('  ConfigDirectory = %s', [Result]));
end;

function SDServiceRequestURL: string;
var
  INI: TINIFile;
begin
  INI := TINIFile.Create(Format('%s\%s', [ConfigDirectory, ConfigFileName]));
  Result := INI.ReadString(INISection_ServiceRequest, INIIdent_RequestURL, '');
  INI.Free;
end;

function SDServiceRequestPort: Cardinal;
var
  INI: TINIFile;
begin
  INI := TINIFile.Create(Format('%s\%s', [ConfigDirectory, ConfigFileName]));
  Result := INI.ReadInteger(INISection_ServiceRequest, INIIdent_RequestPort, 0);
  INI.Free;
end;

function SDCreateSecureMailslot(const AMailslotName: string; out AMailslot: THandle): Boolean;
var
  ea: array [0 .. 0] of EXPLICIT_ACCESS;
  pLocalSystemSID: Pointer;
  dwResult: DWORD;
  NewACL: PACL;
  pSD: PSecurityDescriptor;
  MailSlotSecurityAttributes: Windows.TSecurityAttributes;
begin
  Result := false;

  if Windows.AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0,
    0, 0, 0, 0, pLocalSystemSID) then
  begin
    Log('AllocateAndInitializeSid(BUILTIN\SYSTEM) succeeded.');

    ea[0].grfAccessPermissions := GENERIC_ALL;
    ea[0].grfAccessMode := SET_ACCESS;
    ea[0].grfInheritance := NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm := TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType := TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName := PChar(pLocalSystemSID);

    dwResult := SetEntriesInAcl(High(ea)-Low(ea)+1, @ea, nil, NewACL);
    if (dwResult = ERROR_SUCCESS) then
    begin
      Log('SetEntriesInAcl() succeeded.');
      GetMem(pSD, SECURITY_DESCRIPTOR_MIN_LENGTH);
      if (pSD <> nil) then
      begin
        Log('GetMem() succeeded.');
        if InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION) then
        begin
          Log('InitializeSecurityDescriptor() succeeded.');
          if SetSecurityDescriptorDacl(pSD, true, NewACL, false) then
          begin
            Log('SetSecurityDescriptorDacl() succeeded.');
            MailSlotSecurityAttributes.nLength := SizeOf(TSecurityAttributes);
            MailSlotSecurityAttributes.bInheritHandle := false;
            MailSlotSecurityAttributes.lpSecurityDescriptor := pSD;

            AMailslot := CreateMailslot(PChar('\\.\mailslot\' + AMailslotName), 0, MAILSLOT_WAIT_FOREVER,
              @MailSlotSecurityAttributes);
            if (AMailslot <> INVALID_HANDLE_VALUE) then
            begin
              Log('CreateMailslot() succeeded.');
              Result := true;
            end
            else
            begin
              Log(Format('CreateMailslot() failed: %s', [SysErrorMessage(GetLastError)]));
            end;
          end
          else
          begin
            Log(Format('SetSecurityDescriptorDacl() failed: %s', [SysErrorMessage(GetLastError)]));
          end;
        end
        else
        begin
          Log(Format('InitializeSecurityDescriptor() failed: %s', [SysErrorMessage(GetLastError)]));
        end;
      end
      else
      begin
        Log(Format('GetMem() failed: %s', [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('SetEntriesInAcl() failed: %s', [SysErrorMessage(GetLastError)]));
    end
  end
  else
  begin
    Log(Format('AllocateAndInitializeSid() failed: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDOpenMailslot(const AMailslotName: string; out AMailslot: THandle): Boolean;
begin
  Result := false;
  AMailslot := CreateFile(PChar('\\.\mailslot\' + AMailslotName), GENERIC_WRITE, FILE_SHARE_READ,
    nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if (AMailslot <> INVALID_HANDLE_VALUE) then
  begin
    Log('CreateFile() succeeded.');
    Result := true;
  end
  else
  begin
    Log(Format('CreateFile() failed: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDWriteToMailslot(const AMailslot: THandle; const AMessage: string): Boolean;
var
  cWritten: Cardinal;
begin
  Result := WriteFile(AMailslot, PChar(AMessage)^, (Length(AMessage) + 1) * SizeOf(Char),
    cWritten, nil);
  if Result then
  begin
    Log(Format('WriteFile("%s") succeeded, %d bytes written.', [AMessage, cWritten]));
  end
  else
  begin
    Log(Format('WriteFile("%s") failed: %s', [AMessage, SysErrorMessage(GetLastError)]));
  end;
end;

function SDReadFromMailslot(const AMailslot: THandle; out AMessage: string): Boolean;
var
  cNextMessageSize: Cardinal;
  cMessagesCount: Cardinal;
  Buffer: array of Char;
  cBytesRead: Cardinal;
  // nIndex: Integer;
begin
  Result := false;
  AMessage := '';
  if GetMailslotInfo(AMailslot, nil, cNextMessageSize, @cMessagesCount, nil) then
  begin
    if (cNextMessageSize <> MAILSLOT_NO_MESSAGE) then
    begin
      SetLength(Buffer, cNextMessageSize div SizeOf(Char));
      if ReadFile(AMailslot, Buffer[0], cNextMessageSize, cBytesRead, nil) then
      begin
        Log(Format('ReadFile(%d) succeeded, %d bytes read.', [cNextMessageSize, cBytesRead]));

        // for nIndex := Low(Buffer) to High(Buffer) do
        // begin
        // Log(Format('%.3d: "%s" (%.2x)', [nIndex, Buffer[nIndex], Ord(Buffer[nIndex])]));
        // end;
        AMessage := string(Buffer);
        if Copy(AMessage, Length(AMessage), 1) = #0 then
        begin
          AMessage := Copy(AMessage, 1, Length(AMessage) - 1);
        end;
        Log(Format('"%s"', [AMessage]));
        Result := true;
      end
      else
      begin
        Log(Format('ReadFile(%d) failed: %s', [cNextMessageSize, SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log('cNextMessageSize = MAILSLOT_NO_MESSAGE');
    end;
  end
  else
  begin
    Log(Format('GetMailslotInfo() failed: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDReadFromMailslot(const AMailslot: THandle; out AMessage: string;
  const ATimeout: Cardinal): Boolean;
var
  dtWaitingSince: TDateTime;
begin
  dtWaitingSince := Now;
  Result := SDReadFromMailslot(AMailslot, AMessage);
  while ((not Result) and DateUtils.WithinPastMilliSeconds(Now, dtWaitingSince, ATimeout)) do
  begin
    Sleep(50);
    Result := SDReadFromMailslot(AMailslot, AMessage);
  end;
end;

function SDIsMailslotEmpty(const AMailslot: THandle): Boolean;
var
  cNextMessageSize: Cardinal;
  cMessagesCount: Cardinal;
begin
  Result := true;
  if GetMailslotInfo(AMailslot, nil, cNextMessageSize, @cMessagesCount, nil) then
  begin
    Result := (cNextMessageSize = MAILSLOT_NO_MESSAGE);
  end;
end;

function SDAppInfoLogoFileName(const nApplicationKey: Integer): string;
begin
  if (nApplicationKey >= 0) then
  begin
    Result := Format('Logo%.4d.png', [nApplicationKey]);
  end
  else
  begin
    Result := 'invalid.png';
  end;
end;

function SDAppInfoFullLogoFileName(const nApplicationKey: Integer): string;
begin
  Result := Format('%s\%s', [ConfigDirectory, SDAppInfoLogoFileName(nApplicationKey)]);
  //Log(Format('nApplicationKey: %d', [nApplicationKey]));
  //Log(Format('LogoFileName(%d): %s', [nApplicationKey, SDAppInfoLogoFileName(nApplicationKey)]));
  //Log(Format('ConfigDirectory: %s', [ConfigDirectory]));
  //Log(Format('Result: %s', [Result]));
end;

function SDAppInfoBackgroundBitmapFileName: string;
begin
  Result := Format('%s\%s', [ConfigDirectory, BackgroundBitmapFileName]);
end;

function SDAppInfoApplicationName(const nApplicationKey: Integer): string;
var
  INI: TINIFile;
begin
  if (nApplicationKey >= 0) then
  begin
    INI := TINIFile.Create(Format('%s\%s', [ConfigDirectory, ConfigFileName]));
    Result := INI.ReadString(INISection_Applications, Format('%.4d', [nApplicationKey]), '');
    INI.Free;
  end
  else
  begin
    Result := 'Invalid application key';
  end;
end;

function SDAppInfoApplicationExecutable(const nApplicationKey: Integer): string;
var
  INI: TINIFile;
begin
  if (nApplicationKey >= 0) then
  begin
    INI := TINIFile.Create(Format('%s\%s', [ConfigDirectory, ConfigFileName]));
    Result := INI.ReadString(INISection_Executables, Format('%.4d', [nApplicationKey]), '');
    INI.Free;
  end
  else
  begin
    Result := '';
  end;
end;

function SDAppInfoApplicationCommandLine(const nApplicationKey: Integer): string;
var
  INI: TINIFile;
begin
  if (nApplicationKey >= 0) then
  begin
    INI := TINIFile.Create(Format('%s\%s', [ConfigDirectory, ConfigFileName]));
    Result := INI.ReadString(INISection_CommandLines, Format('%.4d', [nApplicationKey]), '');
    INI.Free;
  end
  else
  begin
    Result := '';
  end;
end;

initialization

FSDLogFileName := SDLogFileName + Copy(ExtractFileName(ParamStr(0)), 1,
  Length(ExtractFileName(ParamStr(0))) - Length(ExtractFileExt(ParamStr(0)))) + SDLogFileNameExt;
Log(Format('%s logging to %s', [ParamStr(0), FSDLogFileName]));
Log(Format('ParamStr(0): "%s"  ParamCount: %d  ParamStr(1): "%s"', [ParamStr(0), ParamCount,
  ParamStr(1)]));

end.
