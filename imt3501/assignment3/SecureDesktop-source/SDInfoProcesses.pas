unit SDInfoProcesses;

interface

uses
  Windows,
  SDCommon;

const
  MAXPROCESSES = 2048;

type
  TProcessData = record
    PID: DWORD;
    SessionID: DWORD;
    FileName: string;
  end;

  TProcesses = record
    ProcessCount: Cardinal;
    Processes: array [0 .. MAXPROCESSES] of TProcessData;
  end;

  THandleProcessFunction = function(var AProcessData: TProcessData): Boolean;
  THandleProcessMethodFunction = function(var AProcessData: TProcessData): Boolean of object;

function WTSGetActiveConsoleSessionId: DWORD; stdcall; external 'Kernel32.dll';

function EnumerateSessions: Boolean;

function GetTokenUser(const hToken: THandle): string;
function GetTokenGroups(const hToken: THandle): string;
function GetTokenSessionId(const hToken: THandle): DWORD;
function GetSidUserName(const ASID: PSID): string;
function IsPrivilegeEnabled(const hToken: THandle; const sPrivilege: string): Boolean;

function SDEnumerateProcesses(var AProcesses: TProcesses; const Verbosity: TSDLogVerbosity)
  : Boolean;
function SDEnumerateProcessesSilently(var AProcesses: TProcesses): Boolean;
function SDDumpProcessName(var AProcessData: TProcessData): Boolean;
function SDDumpProcessThreads(var AProcessData: TProcessData): Boolean;
function SDDumpProcessTokenPrivileges(var AProcessData: TProcessData): Boolean;
function SDLookupAccountBySID(ASID: PSID): string;
function SDDumpAccessMask(const AMask: Cardinal): Boolean;
function SDProcessAllPIDS(var AProcesses: TProcesses; const AFunction: THandleProcessFunction)
  : Boolean; overload;
function SDProcessAllPIDS(var AProcesses: TProcesses; const AFunction: THandleProcessFunction;
  const AExcludeSessionId: Cardinal): Boolean; overload;
function SDProcessAllPIDS(var AProcesses: TProcesses; const AFunction: THandleProcessMethodFunction;
  const AExcludeSessionId: Cardinal): Boolean; overload;
function SDFindPIDWithPrivilege(const APrivilege: string): DWORD;
function SDDumpThreadPrivileges(const AThread: THandle): Boolean;

function SDRetrieveWindowStations: Boolean;
function SDRetrieveDesktops: Boolean;
function SDRetrieveWindowStationsAndDesktops: Boolean;

function SDDumpWindowStationAndDesktopSecurityInformation: Boolean;

implementation

uses
  Classes,
  SysUtils,
  PsAPI,
  AccCtrl,
  SDInfoSecurity, // <- wg. SDDumpACL()
  Tlhelp32;

const
  WTSAPIDLLNAME = 'wtsapi32.dll';
  WTS_CURRENT_SERVER_HANDLE = THandle(0);

type
  PPACL = ^PACL;
  PPSID = ^PSID;
  TPIDS = array [0 .. MAXPROCESSES] of DWORD;

  TWTS_CONNECTSTATE_CLASS = (WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected,
    WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit);

  TWTS_SESSION_INFO = record
    SessionID: DWORD;
    pWinStationName: LPWSTR;
    State: TWTS_CONNECTSTATE_CLASS;
  end;

  PWTS_SESSION_INFO = ^TWTS_SESSION_INFO;

  TWTS_INFO_CLASS = (WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId,
    WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, WTSConnectState,
    WTSClientBuildNumber, WTSClientName, WTSClientDirectory, WTSClientProductId,
    WTSClientHardwareId, WTSClientAddress, WTSClientDisplay, WTSClientProtocolType);

  TWTSSessionInfoArray = array [0 .. 0] of TWTS_SESSION_INFO;
  PWTSSessionInfoArray = ^TWTSSessionInfoArray;

var
  FWindowStations: TStringList;

function GetSecurityInfo(AHandle: THandle; ObjectType: SE_OBJECT_TYPE;
  SecurityInfo: SECURITY_INFORMATION; ppsidOwner: PPSID; ppsidGroup: PPSID; ppDacl, ppSacl: PPACL;
  var ppSecurityDescriptor: Windows.PSecurityDescriptor): DWORD; stdcall;
  external advapi32 name 'GetSecurityInfo';

function WTSEnumerateSessions(hServer: THandle; Reserved: DWORD; Version: DWORD;
  var ppSessionInfo: PWTS_SESSION_INFO; var pCount: DWORD): BOOL; stdcall;
  external WTSAPIDLLNAME name 'WTSEnumerateSessionsW';

function WTSQuerySessionInformation(hServer: THandle; SessionID: DWORD;
  WTSInfoClass: TWTS_INFO_CLASS; var ppBuffer: Pointer; var pBytesReturned: DWORD): BOOL; stdcall;
  external WTSAPIDLLNAME name 'WTSQuerySessionInformationW';

procedure WTSFreeMemory(pMemory: Pointer); stdcall; external WTSAPIDLLNAME name 'WTSFreeMemory';

function EnumerateSessions: Boolean;
var
  paSessionInfo: PWTSSessionInfoArray;
  nSessionsCount: Cardinal;
  nSessionIndex: Integer;
begin
  if WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, PWTS_SESSION_INFO(paSessionInfo),
    nSessionsCount) then
  begin
    Log(Format('WTSEnumerateSessions() succeeded: %d sessions', [nSessionsCount]));
    for nSessionIndex := 0 to nSessionsCount - 1 do
    begin
      Log(Format('Session %d  ID %d', [nSessionIndex, paSessionInfo^[nSessionIndex].SessionID]));
      Log(Format('  Window station: %s', [StrPas(paSessionInfo^[nSessionIndex].pWinStationName)]));
      // if WTSQuerySessionInformation(WTS_CURRENTSERVER_HANDLE, nSessionIndex,  then

    end;
    WTSFreeMemory(paSessionInfo);
    Result := TRUE;
  end
  else
  begin
    Log(Format('WTSEnumerateSessions() failed: %s', [SysErrorMessage(GetLastError)]));
    Result := FALSE;
  end;
end;

function GetSidUserName(const ASID: Windows.PSID): string;
var
  cbName: Cardinal;
  UserName: PChar;
  cbReferencedDomainName: Cardinal;
  ReferencedDomainName: PChar;
  peUse: Cardinal;
begin
  Result := '';
  cbName := 2048 + 1;
  GetMem(UserName, cbName);
  cbReferencedDomainName := 2048 + 1;
  GetMem(ReferencedDomainName, cbReferencedDomainName);
  if LookupAccountSid(nil, ASID, UserName, cbName, ReferencedDomainName, cbReferencedDomainName,
    peUse) then
  begin
    Result := Format('%s\%s', [StrPas(ReferencedDomainName), StrPas(UserName)]);
  end;
end;

function IsPrivilegeEnabled(const hToken: THandle; const sPrivilege: string): Boolean;
var
  RequiredPrivileges: Windows.TPrivilegeSet;
  pfResult: LongBool;
begin
  Result := FALSE;
  RequiredPrivileges.PrivilegeCount := 1;
  Windows.LookupPrivilegeValue(nil, PChar(sPrivilege), RequiredPrivileges.Privilege[0].Luid);
  RequiredPrivileges.Privilege[0].Attributes := SE_PRIVILEGE_ENABLED;
  RequiredPrivileges.Control := PRIVILEGE_SET_ALL_NECESSARY;

  if Windows.PrivilegeCheck(hToken, RequiredPrivileges, pfResult) then
  begin
    Log(Format('PrivilegeCheck(%d, %s) succeeded.', [hToken, sPrivilege]));
    if pfResult then
    begin
      Log(Format('  pfResult: TRUE', []));
      Result := TRUE;
    end
    else
    begin
      Log(Format('  pfResult: FALSE', []));
    end;
  end
  else
  begin
    Log(Format('PrivilegeCheck(%d, %s) failed. LastError: %s', [hToken, sPrivilege,
      SysErrorMessage(GetLastError)]));
  end;
end;

function GetLogonSid(const hToken: THandle): PSID;
var
  dwLength: Cardinal;
  Groups: PTokenGroups;
begin
  Result := nil;
  if (hToken <> 0) then
  begin
    GetTokenInformation(hToken, TokenLogonSid, nil, 0, dwLength);
    if (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
    begin
      GetMem(Groups, dwLength);
      if (Groups <> nil) then
      begin
        if GetTokenInformation(hToken, TokenLogonSid, Groups, dwLength, dwLength) then
        begin
          CopySid(GetLengthSid(Groups^.Groups[0].Sid), Result, Groups^.Groups[0].Sid);
        end
        else
        begin
          FreeAndNil(Groups);
        end;
      end;
    end;
  end
  else
  begin
    SetLastError(ERROR_INVALID_PARAMETER);
  end;
end;

function GetTokenUser(const hToken: THandle): string;
var
  User: PTokenUser;
  cReturnLength: Cardinal;
  cbName: Cardinal;
  UserName: PChar;
  cbReferencedDomainName: Cardinal;
  ReferencedDomainName: PChar;
  peUse: Cardinal;
begin
  Log(Format('GetTokenUser(hToken: %d)', [hToken]));

  GetTokenInformation(hToken, TokenUser, nil, 0, cReturnLength);
  GetMem(User, cReturnLength);

  if (GetTokenInformation(hToken, TokenUser, User, cReturnLength, cReturnLength)) then
  begin
    cbName := 2048 + 1;
    GetMem(UserName, cbName);
    cbReferencedDomainName := 2048 + 1;
    GetMem(ReferencedDomainName, cbReferencedDomainName);
    if LookupAccountSid(nil, User^.User.Sid, UserName, cbName, ReferencedDomainName,
      cbReferencedDomainName, peUse) then
    begin
      Log(Format('LookupAccountSid() succeeded', []));
      Log(Format('User name: %s', [StrPas(UserName)]));
      Log(Format('Domain: %s', [StrPas(ReferencedDomainName)]));
      Result := StrPas(UserName);
    end
    else
    begin
      Result := Format('LookupAccountSid() failed. LastError: %s', [SysErrorMessage(GetLastError)]);
    end;

    Log(Format('User attributes: %s', [IntToHex(User^.User.Attributes, 8)]));
  end
  else
  begin
    Result := Format('GetTokenInformation() failed. LastError: %s',
      [SysErrorMessage(GetLastError)]);
  end;
end;

function GetTokenGroups(const hToken: THandle): string;
var
  Groups: PTokenGroups;
  cReturnLength: Cardinal;
  cbName: Cardinal;
  GroupName: PChar;
  cbReferencedDomainName: Cardinal;
  ReferencedDomainName: PChar;
  peUse: Cardinal;
  nGroupIndex: Integer;
begin
  Log(Format('GetTokenGroups(hToken: %d)', [hToken]));

  GetTokenInformation(hToken, TokenGroups, nil, 0, cReturnLength);
  GetMem(Groups, cReturnLength);

  if (GetTokenInformation(hToken, TokenGroups, Groups, cReturnLength, cReturnLength)) then
  begin
    Log(Format('cReturnLength: %d, Groups^.GroupCount: %d', [cReturnLength, Groups^.GroupCount]));
    Log(Format('SizeOf(TSIDAndAttributes): %d', [SizeOf(TSIDAndAttributes)]));
    Log(Format('Groups: %p, Groups^.GroupCount: %p', [Groups, @Groups^.GroupCount]));
    for nGroupIndex := 0 to (Groups^.GroupCount - 1) do
    begin
      Log(Format('  Groups^.Groups[%.2d].Sid: %p', [nGroupIndex, Groups^.Groups[nGroupIndex].Sid]));
      cbName := 2048 + 1;
      GetMem(GroupName, cbName);
      cbReferencedDomainName := 2048 + 1;
      GetMem(ReferencedDomainName, cbReferencedDomainName);
      if LookupAccountSid(nil, Groups^.Groups[nGroupIndex].Sid, GroupName, cbName,
        ReferencedDomainName, cbReferencedDomainName, peUse) then
      begin
        Log(Format('LookupAccountSid() succeeded', []));
        Log(Format('Group %d domain\name: %s\%s', [nGroupIndex, StrPas(ReferencedDomainName),
          StrPas(GroupName)]));
        Result := StrPas(GroupName);
        FreeMem(ReferencedDomainName);
        FreeMem(GroupName);
      end
      else
      begin
        Result := Format('LookupAccountSid() failed. LastError: %s',
          [SysErrorMessage(GetLastError)]);
        Log(Result);
      end;

      Log(Format('Group %d attributes: %s', [nGroupIndex,
        IntToHex(Groups^.Groups[nGroupIndex].Attributes, 8)]));
      if (Groups^.Groups[nGroupIndex].Attributes AND $04 = $04) then
      begin
        Log(Format('SE_GROUP_ENABLED', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $02 = $02) then
      begin
        Log(Format('SE_GROUP_ENABLED_BY_DEFAULT', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $20 = $20) then
      begin
        Log(Format('SE_GROUP_INTEGRITY', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $40 = $40) then
      begin
        Log(Format('SE_GROUP_INTEGRITY_ENABLED', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $C0000000 = $C0000000) then
      begin
        Log(Format('SE_GROUP_LOGON_ID', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $01 = $01) then
      begin
        Log(Format('SE_GROUP_MANDATORY', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $08 = $08) then
      begin
        Log(Format('SE_GROUP_OWNER', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $20000000 = $20000000) then
      begin
        Log(Format('SE_GROUP_RESOURCE', []));
      end;
      if (Groups^.Groups[nGroupIndex].Attributes AND $10 = $10) then
      begin
        Log(Format('SE_GROUP_USE_FOR_DENY_ONLY', []));
      end;

    end;
  end
  else
  begin
    Result := Format('GetTokenGroups() failed. LastError: %s', [SysErrorMessage(GetLastError)]);
  end;
end;

function GetTokenSessionId(const hToken: THandle): DWORD;
var
  SessionID: DWORD;
  cReturnLength: Cardinal;
begin
  // Log(Format('GetTokenSessionId(hToken: %d)', [hToken]));
  Result := High(SessionID);
  if (GetTokenInformation(hToken, TokenSessionId, @SessionID, SizeOf(SessionID),
    cReturnLength)) then
  begin
    Result := SessionID;
  end;
end;

function SDEnumerateProcesses(var AProcesses: TProcesses; const Verbosity: TSDLogVerbosity)
  : Boolean;
var
  PIDS: TPIDS;
  cBytesReturned: Cardinal;
  nPIDIndex: Integer;
  hProcess: THandle;
  hProcessModule: array [0 .. 1024] of Windows.hModule;
  cbNeeded: Cardinal;
  szProcessName: array [0 .. MAX_PATH] of Char;
  hToken: THandle;
begin
  ZeroMemory(@AProcesses, SizeOf(AProcesses));
  if EnumProcesses(@PIDS, SizeOf(PIDS), cBytesReturned) then
  begin
    Log(Format('EnumProcesses succeeded, cBytesReturned: %d', [cBytesReturned]));
    AProcesses.ProcessCount := cBytesReturned DIV SizeOf(DWORD);
    for nPIDIndex := 0 to AProcesses.ProcessCount - 1 do
    begin
      AProcesses.Processes[nPIDIndex].PID := PIDS[nPIDIndex];

      hProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, FALSE,
        AProcesses.Processes[nPIDIndex].PID);
      if (hProcess <> 0) then
      begin
        if EnumProcessModules(hProcess, @hProcessModule, SizeOf(hProcessModule), cbNeeded) then
        begin
          if (GetModuleBaseName(hProcess, hProcessModule[0], szProcessName,
            SizeOf(szProcessName) DIV SizeOf(Char)) > 0) then
          begin
            // Log('GetModuleBaseName() succeeded.');
          end;
          AProcesses.Processes[nPIDIndex].FileName := StrPas(szProcessName);
        end;

        if OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken) then
        begin
          try
            // GetTokenUser(hToken)
            AProcesses.Processes[nPIDIndex].SessionID := GetTokenSessionId(hToken);
          finally
          end;
        end;
      end;
    end;

    Log(Format('cProcessesCount: %d', [AProcesses.ProcessCount]));
    Result := TRUE;
  end
  else
  begin
    Log(Format('EnumProcesses failed, dwBytesReturned: %d', [cBytesReturned]));
    Result := FALSE;
  end;
end;

function SDEnumerateProcessesSilently(var AProcesses: TProcesses): Boolean;
begin
  Result := SDEnumerateProcesses(AProcesses, lvSilent);
end;

function SDDumpProcessName(var AProcessData: TProcessData): Boolean;
var
  hProcess: THandle;
  hProcessModule: array [0 .. 1024] of Windows.hModule;
  cbNeeded: Cardinal;
  szProcessName: array [0 .. MAX_PATH] of Char;
  nLoadedModule: Cardinal;
begin
  Log(Format('SDDumpProcessName(PID: %d %s)', [AProcessData.PID, AProcessData.FileName]));
  Result := FALSE;
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, FALSE, AProcessData.PID);
  if (hProcess <> 0) then
  begin
    if EnumProcessModules(hProcess, @hProcessModule, SizeOf(hProcessModule), cbNeeded) then
    begin
      Log(Format('EnumProcessModules succeeded', []));
      // GetModuleBaseName(hProcess, hModule[0], szProcessName,
      // SizeOf(szProcessName) DIV SizeOf(Char));
      // AProcessData.FileName := StrPas(szProcessName);
      // Log(Format('szProcessName: %s', [AProcessData.FileName]));
      for nLoadedModule := 0 to (cbNeeded DIV SizeOf(Windows.hModule)) - 1 do
      begin
        if (GetModuleFileNameEx(hProcess, hProcessModule[nLoadedModule], szProcessName,
          SizeOf(szProcessName)) <> 0) then
        begin
          Log(Format('    %s (%d)', [StrPas(szProcessName), hProcessModule[nLoadedModule]]));
        end;
      end;
      Result := TRUE;
    end
    else
    begin
      Log(Format('EnumProcessModules failed, SizeOf(hModule): %d, cbNeeded: %d',
        [SizeOf(hProcessModule), cbNeeded]));
    end;
  end
  else
  begin
    Log(Format('OpenProcess() failed, LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
  CloseHandle(hProcess);
end;

function SDDumpProcessThreads(var AProcessData: TProcessData): Boolean;
var
  hThreadSnap: THandle;
  ThreadEntry: TThreadEntry32;
begin
  Log(Format('SDDumpProcessThreads(PID: %d %s)', [AProcessData.PID, AProcessData.FileName]));
  Result := FALSE;

  // Take a snapshot of all running threads
  hThreadSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hThreadSnap <> INVALID_HANDLE_VALUE) then
  begin
    // Fill in the size of the structure before using it.
    ThreadEntry.dwSize := SizeOf(TThreadEntry32);

    // Retrieve information about the first thread, and exit if unsuccessful
    if (Thread32First(hThreadSnap, ThreadEntry)) then
    begin
      // Now walk the thread list of the system,
      // and display information about each thread
      // associated with the specified process
      repeat
        if (ThreadEntry.th32OwnerProcessID = AProcessData.PID) then
        begin
          Log(Format('    Thread ID: %d', [ThreadEntry.th32ThreadID]));
          Log(Format('    Thread desktop: %d', [GetThreadDesktop(ThreadEntry.th32ThreadID)]));
        end;
      until (NOT Thread32Next(hThreadSnap, ThreadEntry));
      // Don't forget to clean up the snapshot object.
      CloseHandle(hThreadSnap);
      Result := TRUE;
    end
    else
    begin
      Log(Format('Thread32First() failed: %s', [SysErrorMessage(GetLastError)]));
      // Must clean up the snapshot object!
      CloseHandle(hThreadSnap);
    end;
  end;
end;

function SDDumpProcessTokenPrivileges(var AProcessData: TProcessData): Boolean;
var
  hProcess: THandle;
  hToken: THandle;
  nReturnLength: Cardinal;
  lpvTokenInformation: PTokenPrivileges;
  dwTokenInformationLength: DWORD;
  nPrivilegeNameSize: Cardinal;
  szPrivilegeName: PChar;
  nPrivilegeDisplayNameSize: Cardinal;
  szPrivilegeDisplayName: PChar;
  nPrivilegeIndex: Integer;
  lpLanguageId: Cardinal;
begin
  Log(Format('SDDumpProcessTokenPrivileges(PID: %d %s)', [AProcessData.PID,
    AProcessData.FileName]));
  Result := FALSE;
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, FALSE, AProcessData.PID);
  if (hProcess <> 0) then
  begin
    if OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken) then
    begin
      Log(Format('OpenProcessToken() succeeded', []));
      try
        if GetTokenInformation(hToken, TokenPrivileges, nil, 0, nReturnLength) then
        begin
          Log('Success: GetTokenInformation()');
          Log(Format('hToken:                   %d', [hToken]));
          Log(Format('nReturnLength:            %d', [nReturnLength]));
        end
        else
        begin
          Log('Failed: GetTokenInformation()');
          Log(Format('hToken:                   %d', [hToken]));
          Log(Format('nReturnLength:            %d', [nReturnLength]));
          GetMem(lpvTokenInformation, nReturnLength);
          dwTokenInformationLength := nReturnLength;
          if GetTokenInformation(hToken, TokenPrivileges, lpvTokenInformation,
            dwTokenInformationLength, nReturnLength) then
          begin
            Log('Success: GetTokenInformation()');
            Log(Format('hToken:                   %d', [hToken]));
            // Debug(Format('lpvTokenInformation^: ', [lpvTokenInformation^]));
            Log(Format('dwTokenInformationLength: %d', [dwTokenInformationLength]));
            Log(Format('nReturnLength:            %d', [nReturnLength]));

            nPrivilegeNameSize := 255;
            GetMem(szPrivilegeName, nPrivilegeNameSize);
            nPrivilegeDisplayNameSize := 255;
            GetMem(szPrivilegeDisplayName, nPrivilegeDisplayNameSize);
            for nPrivilegeIndex := 0 to lpvTokenInformation.PrivilegeCount - 1 do
            begin
              nPrivilegeNameSize := 255;
              nPrivilegeDisplayNameSize := 255;
              LookupPrivilegeName(nil, lpvTokenInformation.Privileges[nPrivilegeIndex].Luid,
                szPrivilegeName, nPrivilegeNameSize);
              LookupPrivilegeDisplayName(nil, szPrivilegeName, szPrivilegeDisplayName,
                nPrivilegeDisplayNameSize, lpLanguageId);
              Log(Format('%s -- %s', [StrPas(szPrivilegeName), StrPas(szPrivilegeDisplayName)]));
            end;
          end
          else
          begin
            Log('Failed: GetTokenInformation()');
            Log(Format('hToken:                   %d', [hToken]));
            Log(Format('nReturnLength:            %d', [nReturnLength]));
          end;
        end;
      except
        Log(Format('  LastError: %s', [SysErrorMessage(GetLastError)]));
      end;
      Result := TRUE;
    end
    else
    begin
      Log(Format('OpenProcessToken failed, hProcess: %d, LastError: %s',
        [hProcess, SysErrorMessage(GetLastError)]));
    end;
  end
  else
  begin
    Log(Format('OpenProcess() failed, LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
  CloseHandle(hProcess);
end;

function SDLookupAccountBySID(ASID: Windows.PSID): string;
var
  AccountName: string;
  Domain: string;
  cchName: Cardinal;
  cchDomain: Cardinal;
  peUse: Cardinal;
begin
  cchName := 0;
  cchDomain := 0;
  LookupAccountSid(nil, ASID, nil, cchName, nil, cchDomain, peUse);
  SetLength(AccountName, cchName);
  SetLength(Domain, cchDomain);
  LookupAccountSid(nil, ASID, PChar(AccountName), cchName, PChar(Domain), cchDomain, peUse);
  Result := PChar(Domain) + '\' + PChar(AccountName);
end;

function SDDumpAccessMask(const AMask: Cardinal): Boolean;
type
  TAccessRight = record
    Value: Cardinal;
    Name: string;
  end;
const
  AccessRight: array [0 .. 21] of TAccessRight = ((Value: 0; Name: '(Start)'), (Value: $00010000;
    Name: '_DELETE'), (Value: $0001; Name: 'DESKTOP_READOBJECTS'), (Value: $0002;
    Name: 'DESKTOP_CREATEWINDOW'), (Value: $0004; Name: 'DESKTOP_CREATEMENU'), (Value: $0008;
    Name: 'DESKTOP_HOOKCONTROL'), (Value: $0010; Name: 'DESKTOP_JOURNALRECORD'), (Value: $0020;
    Name: 'DESKTOP_JOURNALPLAYBACK'), (Value: $0040; Name: 'DESKTOP_ENUMERATE'), (Value: $0080;
    Name: 'DESKTOP_WRITEOBJECTS'), (Value: $0100; Name: 'DESKTOP_SWITCHDESKTOP'), (Value: $0000FFFF;
    Name: 'SPECIFIC_RIGHTS_ALL'), (Value: $00020000; Name: 'READ_CONTROL'), (Value: $00040000;
    Name: 'WRITE_DAC'), (Value: $00080000; Name: 'WRITE_OWNER'), (Value: $001F0000;
    Name: 'STANDARD_RIGHTS_ALL'), (Value: $01000000; Name: 'ACCESS_SYSTEM_SECURITY'),
    (Value: $02000000; Name: 'MAXIMUM_ALLOWED'), (Value: $10000000; Name: 'GENERIC_ALL'),
    (Value: $20000000; Name: 'GENERIC_EXECUTE'), (Value: $40000000; Name: 'GENERIC_WRITE'),
    (Value: $80000000; Name: 'GENERIC_READ'));
var
  nAccessRightIndex: Integer;
begin
  // Windows.GENERIC_READ

  for nAccessRightIndex := Low(AccessRight) to High(AccessRight) do
  begin
    if ((AMask AND AccessRight[nAccessRightIndex].Value) = AccessRight[nAccessRightIndex]
      .Value) then
    begin
      Log(Format('%s - %s', [IntToHex(AccessRight[nAccessRightIndex].Value, 8),
        AccessRight[nAccessRightIndex].Name]));
    end;
  end;
  Result := TRUE;
end;

function SDProcessAllPIDS(var AProcesses: TProcesses;
  const AFunction: THandleProcessFunction): Boolean;
var
  nProcessIndex: Integer;
begin
  Result := TRUE;
  for nProcessIndex := 0 to AProcesses.ProcessCount - 1 do
  begin
    Result := AFunction(AProcesses.Processes[nProcessIndex]);
  end;
end;

function SDProcessAllPIDS(var AProcesses: TProcesses; const AFunction: THandleProcessFunction;
  const AExcludeSessionId: Cardinal): Boolean;
var
  nProcessIndex: Integer;
begin
  Result := TRUE;
  for nProcessIndex := 0 to AProcesses.ProcessCount - 1 do
  begin
    if (AProcesses.Processes[nProcessIndex].SessionID <> AExcludeSessionId) then
    begin
      Result := AFunction(AProcesses.Processes[nProcessIndex]);
    end;
  end;
end;

function SDProcessAllPIDS(var AProcesses: TProcesses; const AFunction: THandleProcessMethodFunction;
  const AExcludeSessionId: Cardinal): Boolean; overload;
var
  nProcessIndex: Integer;
begin
  Result := TRUE;
  for nProcessIndex := 0 to AProcesses.ProcessCount - 1 do
  begin
    if (AProcesses.Processes[nProcessIndex].SessionID <> AExcludeSessionId) then
    begin
      Result := AFunction(AProcesses.Processes[nProcessIndex]);
    end;
  end;
end;

function SDFindPIDWithPrivilege(const APrivilege: string): DWORD;
var
  Processes: TProcesses;
  nProcessIndex: Integer;
  AProcessData: TProcessData;
  hProcess: THandle;
  hToken: THandle;
  nReturnLength: Cardinal;
  lpvTokenInformation: PTokenPrivileges;
  dwTokenInformationLength: DWORD;
  nPrivilegeNameSize: Cardinal;
  szPrivilegeName: PChar;
  nPrivilegeIndex: Integer;
begin
  Log(Format('SDFindPIDWithPrivilege(%s)', [APrivilege]));
  Result := 0;
  if SDEnumerateProcessesSilently(Processes) then
  begin
    for nProcessIndex := Low(Processes.Processes)
      to ( Low(Processes.Processes) + Processes.ProcessCount - 1) do
    begin
      AProcessData := Processes.Processes[nProcessIndex];
      hProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, FALSE,
        AProcessData.PID);
      if (hProcess <> 0) then
      begin
        if OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken) then
        begin
          // Log(Format('OpenProcessToken() succeeded', []));
          try
            if GetTokenInformation(hToken, TokenPrivileges, nil, 0, nReturnLength) then
            begin
              Log('Success: GetTokenInformation()');
              Log(Format('hToken:                   %d', [hToken]));
              Log(Format('nReturnLength:            %d', [nReturnLength]));
            end
            else
            begin
              // Log('Failed: GetTokenInformation()');
              // Log(Format('hToken:                   %d', [hToken]));
              // Log(Format('nReturnLength:            %d', [nReturnLength]));
              GetMem(lpvTokenInformation, nReturnLength);
              dwTokenInformationLength := nReturnLength;
              if GetTokenInformation(hToken, TokenPrivileges, lpvTokenInformation,
                dwTokenInformationLength, nReturnLength) then
              begin
                // Log('Success: GetTokenInformation()');
                // Log(Format('hToken:                   %d', [hToken]));
                // Debug(Format('lpvTokenInformation^: ', [lpvTokenInformation^]));
                // Log(Format('dwTokenInformationLength: %d', [dwTokenInformationLength]));
                // Log(Format('nReturnLength:            %d', [nReturnLength]));

                nPrivilegeNameSize := 255;
                GetMem(szPrivilegeName, nPrivilegeNameSize);
                for nPrivilegeIndex := 0 to lpvTokenInformation.PrivilegeCount - 1 do
                begin
                  nPrivilegeNameSize := 255;
                  LookupPrivilegeName(nil, lpvTokenInformation.Privileges[nPrivilegeIndex].Luid,
                    szPrivilegeName, nPrivilegeNameSize);
                  // Log(Format('%s -- %s', [StrPas(szPrivilegeName), APrivilege]));
                  if (StrPas(szPrivilegeName) = APrivilege) then
                  begin
                    Result := AProcessData.PID;
                    Log(Format('Found process %d with privilege %s',
                      [AProcessData.PID, APrivilege]));
                  end;
                end;
              end
              else
              begin
                Log('Failed: GetTokenInformation()');
                Log(Format('hToken:                   %d', [hToken]));
                Log(Format('nReturnLength:            %d', [nReturnLength]));
              end;
            end;
          except
            Log(Format('  LastError: %s', [SysErrorMessage(GetLastError)]));
          end;
          CloseHandle(hToken);
        end
        else
        begin
          Log(Format('OpenProcessToken failed, hProcess: %d, LastError: %s',
            [hProcess, SysErrorMessage(GetLastError)]));
        end;
      end
      else
      begin
        Log(Format('OpenProcess() failed, LastError: %s', [SysErrorMessage(GetLastError)]));
      end;
      CloseHandle(hProcess);
    end;
  end;
end;

function SDDumpThreadPrivileges(const AThread: THandle): Boolean;
var
  hToken: THandle;
  lpvTokenInformation: PTokenPrivileges;
  dwTokenInformationLength: DWORD;
  nReturnLength: Cardinal;
  nPrivilegeNameSize: Cardinal;
  szPrivilegeName: PChar;
  nPrivilegeDisplayNameSize: Cardinal;
  szPrivilegeDisplayName: PChar;
  nPrivilegeIndex: Integer;
  lpLanguageId: Cardinal;
begin
  Result := FALSE;
  if (NOT OpenThreadToken(AThread, TOKEN_READ, FALSE, hToken)) then
  begin
    ImpersonateSelf(SecurityImpersonation);
  end;

  if OpenThreadToken(AThread, TOKEN_READ, FALSE, hToken) then
  begin
    Log(Format('OpenThreadToken() succeeded. hToken: %d', [hToken]));
    if GetTokenInformation(hToken, TokenPrivileges, nil, 0, nReturnLength) then
    begin
      Log('Success: GetTokenInformation()');
      Log(Format('hToken:                   %d', [hToken]));
      Log(Format('nReturnLength:            %d', [nReturnLength]));
    end
    else
    begin
      Log('Failed: GetTokenInformation()');
      Log(Format('hToken:                   %d', [hToken]));
      Log(Format('nReturnLength:            %d', [nReturnLength]));
      GetMem(lpvTokenInformation, nReturnLength);
      dwTokenInformationLength := nReturnLength;
      if GetTokenInformation(hToken, TokenPrivileges, lpvTokenInformation, dwTokenInformationLength,
        nReturnLength) then
      begin
        Log('Success: GetTokenInformation()');
        Log(Format('hToken:                   %d', [hToken]));
        // Debug(Format('lpvTokenInformation^: ', [lpvTokenInformation^]));
        Log(Format('dwTokenInformationLength: %d', [dwTokenInformationLength]));
        Log(Format('nReturnLength:            %d', [nReturnLength]));

        nPrivilegeNameSize := 255;
        GetMem(szPrivilegeName, nPrivilegeNameSize);
        nPrivilegeDisplayNameSize := 255;
        GetMem(szPrivilegeDisplayName, nPrivilegeDisplayNameSize);
        for nPrivilegeIndex := 0 to lpvTokenInformation.PrivilegeCount - 1 do
        begin
          nPrivilegeNameSize := 255;
          nPrivilegeDisplayNameSize := 255;
          LookupPrivilegeName(nil, lpvTokenInformation.Privileges[nPrivilegeIndex].Luid,
            szPrivilegeName, nPrivilegeNameSize);
          LookupPrivilegeDisplayName(nil, szPrivilegeName, szPrivilegeDisplayName,
            nPrivilegeDisplayNameSize, lpLanguageId);
          Log(Format('%s -- %s', [StrPas(szPrivilegeName), StrPas(szPrivilegeDisplayName)]));
        end;
        Result := TRUE;
      end
      else
      begin
        Log('Failed: GetTokenInformation()');
        Log(Format('hToken:                   %d', [hToken]));
        Log(Format('nReturnLength:            %d', [nReturnLength]));
      end;
    end;
  end
  else
  begin
    Log(Format('OpenThreadToken() failed. LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDRetrieveWindowStations: Boolean;

  function SDEnumWindowStationsCallBackProc(lpszWindowStation: LPWSTR; lParam: lParam)
    : BOOL; stdcall;
  var
    sWindowStationName: UnicodeString;
  begin
    sWindowStationName := lpszWindowStation;
    Log(Format('EnumWindowStationsCallBackProc(lpszWindowStation: "%s"; lParam: %d',
      [sWindowStationName, lParam]));
    FWindowStations.Add(sWindowStationName);
    FWindowStations.Objects[FWindowStations.Count - 1] := TStringList.Create;
    Log(Format('Window station %d: %s', [FWindowStations.Count - 1, sWindowStationName]));
    Result := TRUE;
  end;

begin
  Log('SDRetrieveWindowStations()');
  Result := FALSE;
  FWindowStations.Clear;
  Log('Calling EnumWindowStations()');
  if Windows.EnumWindowStations(@SDEnumWindowStationsCallBackProc, 0) then
  begin
    Log('EnumWindowStations() succeeded');
    Result := TRUE;
  end
  else
  begin
    Log('EnumWindowStations() failed');
    Log(Format('LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
  Log('EnumWindowStations() called');
end;

function SDRetrieveDesktops: Boolean;

  function EnumDesktopsCallBackProc(const lpszDesktop: LPWSTR; const lParam: lParam): BOOL; stdcall;
  begin
    (FWindowStations.Objects[lParam] AS TStringList).Add(lpszDesktop);
    Log(Format('Desktop for %d: %s', [lParam, lpszDesktop]));
    Result := TRUE;
  end;

var
  nIndex: Integer;
  hWindowStation: THandle;

begin
  Log('SDRetrieveDesktops()');
  if (FWindowStations.Count = 0) then
  begin
    SDRetrieveWindowStations;
  end;

  Result := FALSE;
  Log('Iterating through window stations');
  for nIndex := 0 to FWindowStations.Count - 1 do
  begin
    (FWindowStations.Objects[nIndex] AS TStringList).Clear;
    Log(Format('Evaluating window station %d (%d in total)', [nIndex, FWindowStations.Count]));
    Log(Format('Calling OpenWindowStation("%s")', [FWindowStations[nIndex]]));

    hWindowStation := OpenWindowStation(PChar(FWindowStations[nIndex]), FALSE, WINSTA_ENUMERATE OR
      WINSTA_ENUMDESKTOPS);
    Log(Format('hWindowStation: %d', [hWindowStation]));
    if (hWindowStation <> 0) then
    begin
      Log('OpenWindowStation() succeeded');

      if Windows.EnumDesktops(hWindowStation, @EnumDesktopsCallBackProc, nIndex) then
      begin
        Log('EnumDesktops() succeeded');
        Result := TRUE;
      end
      else
      begin
        Log(Format('EnumDesktops() failed for %d: %s', [nIndex, SysErrorMessage(GetLastError)]));
      end;

      CloseWindowStation(hWindowStation);
    end
    else
    begin
      Log(Format('OpenWindowStation() failed for "%s": %s', [FWindowStations[nIndex],
        SysErrorMessage(GetLastError)]));
    end;
  end;
end;

function SDRetrieveWindowStationsAndDesktops: Boolean;
begin
  Result := SDRetrieveWindowStations;
  Result := Result AND SDRetrieveDesktops;
end;

function SDDumpWindowStationAndDesktopSecurityInformation: Boolean;
var
  nWindowStationIndex: Integer;
  hOldWindowStation: THandle;
  hNewWindowStation: THandle;
  hInputDesktop: THandle;
  cLengthNeeded: Cardinal;
  lpszDesktopName: Pointer;
  hDesktop: HDESK;
  Desktops: TStringList;
  nDesktopIndex: Integer;
  SIRequested: SECURITY_INFORMATION;
  ppsidOwner: PPSID;
  ppsidGroup: PPSID;
  ppDacl: PPACL;

  dwResult: DWORD;
  pSecDescriptor: Windows.PSecurityDescriptor;
  nLengthNeeded: Cardinal;
  nBytesReserved: Integer;
begin
  Log('SDDumpWindowStationAndDesktopSecurityInformation()');
  for nWindowStationIndex := 0 to FWindowStations.Count - 1 do
  begin
    hOldWindowStation := GetProcessWindowStation;
    Log(Format('hOldWindowStation: %d', [hOldWindowStation]));
    hNewWindowStation := OpenWindowStation(PChar(FWindowStations[nWindowStationIndex]), FALSE,
      WINSTA_ENUMERATE OR WINSTA_ENUMDESKTOPS or READ_CONTROL);
    Log(Format('hNewWindowStation: %d', [hNewWindowStation]));
    if (hNewWindowStation <> 0) then
    begin
      Log(Format('OpenWindowStation(%s) succeeded', [PChar(FWindowStations[nWindowStationIndex])]));

      SIRequested := OWNER_SECURITY_INFORMATION OR GROUP_SECURITY_INFORMATION OR
        DACL_SECURITY_INFORMATION; // or SACL_SECURITY_INFORMATION;
      ppsidOwner := nil;
      ppsidGroup := nil;
      ppDacl := nil;
      pSecDescriptor := NIL;

      dwResult := GetSecurityInfo(hNewWindowStation, SE_WINDOW_OBJECT, SIRequested, ppsidOwner,
        ppsidGroup, ppDacl, nil, pSecDescriptor);
      if dwResult = ERROR_SUCCESS then
      begin
        Log(Format('GetSecurityInfo() succeeded', []));
        SDDumpSecurityInfo(pSecDescriptor);
      end
      else
      begin
        Log(Format('GetSecurityInfo() failed: %d, LastError: %s',
          [dwResult, SysErrorMessage(GetLastError)]));
      end;

      if SetProcessWindowStation(hNewWindowStation) then
      begin
        Log('SetProcessWindowStation(hNewWindowStation) succeeded.');
        Log(Format('Window station: %s', [FWindowStations[nWindowStationIndex]]));

        hInputDesktop := Windows.OpenInputDesktop(0, FALSE, READ_CONTROL);
        if (hInputDesktop <> 0) then
        begin
          Log(Format('OpenInputDesktop() succeeded: hInputDesktop = %d', [hInputDesktop]));
          Windows.GetUserObjectInformation(hInputDesktop, UOI_NAME, nil, 0, cLengthNeeded);
          Log(Format('cLengthNeeded: %d', [cLengthNeeded]));
          GetMem(lpszDesktopName, cLengthNeeded);
          if Windows.GetUserObjectInformation(hInputDesktop, UOI_NAME, lpszDesktopName,
            cLengthNeeded, cLengthNeeded) then
          begin
            Log('GetUserObjectInformation() succeeded.');
            Log(Format('UOI_NAME: %s', [PChar(lpszDesktopName)]));
            Log('UOI_NAME retrieved.');
          end
          else
          begin
            Log(Format('GetUserObjectInformation() failed: %s', [SysErrorMessage(GetLastError)]));
          end;
        end
        else
        begin
          Log(Format('OpenInputDesktop() failed: %s', [SysErrorMessage(GetLastError)]));
        end;

        Desktops := (FWindowStations.Objects[nWindowStationIndex] AS TStringList);
        for nDesktopIndex := 0 to Desktops.Count - 1 do
        begin
          Log(Format('Desktop: %s', [Desktops[nDesktopIndex]]));
          hDesktop := Windows.OpenDesktop(PChar(Desktops[nDesktopIndex]), 0, FALSE,
            // DESKTOP_CREATEMENU OR
            // DESKTOP_CREATEWINDOW OR DESKTOP_ENUMERATE OR DESKTOP_HOOKCONTROL OR
            // DESKTOP_JOURNALPLAYBACK OR
            // DESKTOP_JOURNALRECORD OR DESKTOP_READOBJECTS OR DESKTOP_SWITCHDESKTOP OR
            // DESKTOP_WRITEOBJECTS OR
            READ_CONTROL);
          if hDesktop = 0 then
          begin
            Log(Format('OpenDesktop() failed: %s', [SysErrorMessage(GetLastError)]));
          end
          else
          begin
            Log(Format('OpenDesktop(%s), handle: %d', [Desktops[nDesktopIndex], hDesktop]));
            SIRequested := OWNER_SECURITY_INFORMATION OR GROUP_SECURITY_INFORMATION OR
              DACL_SECURITY_INFORMATION; // or SACL_SECURITY_INFORMATION;
            pSecDescriptor := NIL;
            Windows.GetUserObjectSecurity(hDesktop, SIRequested, pSecDescriptor, 0, nLengthNeeded);
            // meMessages.Lines.Add(Format('GetUserObjectSecurity() completed. LastError: %s',
            // [SysErrorMessage(GetLastError)]));
            nBytesReserved := nLengthNeeded;
            GetMem(pSecDescriptor, nLengthNeeded);
            SIRequested := OWNER_SECURITY_INFORMATION OR GROUP_SECURITY_INFORMATION OR
              DACL_SECURITY_INFORMATION; // or
            // SACL_SECURITY_INFORMATION;
            if Windows.GetUserObjectSecurity(hDesktop, SIRequested, pSecDescriptor, nBytesReserved,
              nLengthNeeded) then
            begin
              Log(Format('GetUserObjectSecurity() succeeded', []));
              SDDumpSecurityInfo(pSecDescriptor);
            end
            else
            begin
              Log(Format('GetUserObjectSecurity() failed. ' + 'nBytesReserved: %d, ' +
                'nLengthNeeded: %d, ' + 'LastError: %s', [nBytesReserved, nLengthNeeded,
                SysErrorMessage(GetLastError)]));
            end;
          end;
          CloseDesktop(hDesktop);
        end;
      end
      else
      begin
        Log(Format('SetProcessWindowStation(hNewWindowStation) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;
      if SetProcessWindowStation(hOldWindowStation) then
      begin
        Log('SetProcessWindowStation(hOldWindowStation) succeeded.');
      end
      else
      begin
        Log(Format('SetProcessWindowStation(hOldWindowStation) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;
      CloseWindowStation(hNewWindowStation);
    end
    else
    begin
      Log(Format('OpenWindowStation() failed for "%s": %s', [FWindowStations[nWindowStationIndex],
        SysErrorMessage(GetLastError)]));
      Log('Trying to open while requesting fewer access rights');

      hNewWindowStation := OpenWindowStation(PChar(FWindowStations[nWindowStationIndex]), FALSE,
        READ_CONTROL);
      Log(Format('hNewWindowStation: %d', [hNewWindowStation]));
      if (hNewWindowStation <> 0) then
      begin
        Log(Format('OpenWindowStation(%s) succeeded',
          [PChar(FWindowStations[nWindowStationIndex])]));

        SIRequested := OWNER_SECURITY_INFORMATION OR GROUP_SECURITY_INFORMATION OR
          DACL_SECURITY_INFORMATION; // or SACL_SECURITY_INFORMATION;
        ppsidOwner := nil;
        ppsidGroup := nil;
        ppDacl := nil;
        pSecDescriptor := NIL;

        dwResult := GetSecurityInfo(hNewWindowStation, SE_WINDOW_OBJECT, SIRequested, ppsidOwner,
          ppsidGroup, ppDacl, nil, pSecDescriptor);
        if dwResult = ERROR_SUCCESS then
        begin
          Log(Format('GetSecurityInfo() succeeded', []));
          SDDumpSecurityInfo(pSecDescriptor);
        end
        else
        begin
          Log(Format('GetSecurityInfo() failed: %d, LastError: %s',
            [dwResult, SysErrorMessage(GetLastError)]));
        end;
      end;
    end;
  end;
  Result := TRUE;
end;

initialization

FWindowStations := TStringList.Create;

end.
