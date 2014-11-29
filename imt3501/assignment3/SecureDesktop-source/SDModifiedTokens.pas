unit SDModifiedTokens;

interface

uses
//  JwaWindows,
  Windows;

function SDAddSecureViewerProcessGroup: Boolean;
function SDRemoveSecureViewerProcessGroup: Boolean;
function SDGetSecureViewerProcessGroupName: string;
function SDGetSecureViewerProcessGroupSID: PSID;

function SDCreateSecureDesktop(const ADesktopName: string): THandle;
function SDClearSecureDesktop(const ADesktopName: string): Boolean;

function SDCreateProcessWithTokenOnDesktop(const AModuleName: string; const ACommandLine: string;
  const AToken: THandle; const ADesktopName: string): Boolean;
function SDCreateProcessOnDesktop(const AModuleName: string; const ACommandLine: string;
  const ADesktopName: string): Boolean;
function SDCreateProcess(const AModuleName: string; const ACommandLine: string): Boolean;

function SDAcquireTCBPrivilege: Boolean;
function SDReleaseTCBPrivilege: Boolean;

// function SDAddGroupToToken(const AToken: THandle; const AGroupName: string): Windows.PHandle;
function SDAddGroupToToken(const AToken: THandle; const ASID: Pointer): Windows.PTokenGroups;

implementation

uses
  AccCtrl,
  AclApi,
  SysUtils,
  SDCommon,
  SDInfoProcesses;

const
  // LMErr.h
  NERR_Success = 0;
  NERR_BASE = 2100;
  NERR_GroupExists = NERR_BASE + 123;
  NERR_InvalidComputer = NERR_BASE + 251;
  NERR_NotPrimary = NERR_BASE + 126;
  NERR_UserExists = NERR_BASE + 124;
  NERR_GroupNotFound = NERR_BASE + 120;

type
  // LMaccess.h
  _LOCALGROUP_INFO_0 = record
    lgrpi0_name: LPWSTR;
  end;

  // winternl.h
  _UNICODE_STRING = packed record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWideChar;
  end;
  PUNICODE_STRING = ^_UNICODE_STRING;

  _OBJECT_ATTRIBUTES = packed record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: ULONG;
    SecurityDescriptor: PVOID;
    SecurityQualityOfService: PVOID;
  end;
  POBJECT_ATTRIBUTES = ^_OBJECT_ATTRIBUTES;

var
  FSecureViewerProcessGroupName: string;

  // LMaccess.h
function NetLocalGroupAdd(servername: LPCWSTR; level: DWORD; buf: LPBYTE;
  parm_err: LPDWORD): DWORD; stdcall; external 'netapi32';
function NetLocalGroupDel(servername: LPCWSTR; groupname: LPCWSTR): DWORD; stdcall;
  external 'netapi32';

  // Sddl.h
function ConvertSidToStringSid(Sid: PSID; var StringSid: LPWSTR): BOOL; stdcall;
  external 'advapi32';

function ZwCreateToken(TokenHandle: PHANDLE; DesiredAccess: ACCESS_MASK;
  ObjectAttributes: POBJECT_ATTRIBUTES; // POBJECT_ATTRIBUTES;
  ATokenType: Windows.TTokenType; // TOKEN_TYPE;
  AuthenticationId: PLUID; ExpirationTime: Windows.PLargeInteger; // PLARGE_INTEGER;
  User: Windows.PTokenUser; Groups: Windows.PTokenGroups; Privileges: Windows.PTokenPrivileges;
  Owner: Windows.PTokenOwner; PrimaryGroup: Windows.PTokenPrimaryGroup;
  DefaultDacl: Windows.PTokenDefaultDacl; Source: Windows.PTokenSource): Cardinal; stdcall;
  external 'ntdll' name 'NtCreateToken';

function SDAddSecureViewerProcessGroup: Boolean;
var
  GroupInfo: _LOCALGROUP_INFO_0;
  parm_err: PDWORD;
  nResult: Cardinal;
begin
  FSecureViewerProcessGroupName := SecureViewerProcessGroupBaseName;
  nResult := 0;
  repeat
    if (nResult AND ERROR_ALIAS_EXISTS = ERROR_ALIAS_EXISTS) then
    begin
      FSecureViewerProcessGroupName :=
        Format('%s-%.5d', [SecureViewerProcessGroupBaseName, Random(100000)]);
    end;
    GroupInfo.lgrpi0_name := PChar(FSecureViewerProcessGroupName);
    parm_err := nil;
    nResult := NetLocalGroupAdd(nil, 0, @GroupInfo, parm_err);
    Result := (nResult = NERR_Success);
  until (NOT(nResult AND ERROR_ALIAS_EXISTS = ERROR_ALIAS_EXISTS));
  Log(Format('Added group FSecureViewerProcessGroupName: %s', [FSecureViewerProcessGroupName]));

  if (NOT Result) then
  begin
    Log(Format('NetLocalGroupAdd() failed. nResult: %d', [nResult]));
    if (nResult AND ERROR_ACCESS_DENIED = ERROR_ACCESS_DENIED) then
    begin
      Log('  ERROR_ACCESS_DENIED');
    end;
    if (nResult AND ERROR_ALIAS_EXISTS = ERROR_ALIAS_EXISTS) then
    begin
      Log('  ERROR_ALIAS_EXISTS');
    end;
    if (nResult AND ERROR_INVALID_LEVEL = ERROR_INVALID_LEVEL) then
    begin
      Log('  ERROR_INVALID_LEVEL');
    end;
    if (nResult AND ERROR_INVALID_PARAMETER = ERROR_INVALID_PARAMETER) then
    begin
      Log('  ERROR_INVALID_PARAMETER');
    end;
    if (nResult AND NERR_GroupExists = NERR_GroupExists) then
    begin
      Log('  NERR_GroupExists');
    end;
    if (nResult AND NERR_InvalidComputer = NERR_InvalidComputer) then
    begin
      Log('  NERR_InvalidComputer');
    end;
    if (nResult AND NERR_NotPrimary = NERR_NotPrimary) then
    begin
      Log('  NERR_NotPrimary');
    end;
    if (nResult AND NERR_UserExists = NERR_UserExists) then
    begin
      Log('  NERR_UserExists');
    end;
  end;
end;

function SDRemoveSecureViewerProcessGroup: Boolean;
var
  nResult: Cardinal;
begin
  nResult := NetLocalGroupDel(nil, PChar(FSecureViewerProcessGroupName));
  Result := (nResult = NERR_Success);
  if Result then
  begin
    Log(Format('Removed group FSecureViewerProcessGroupName: %s', [FSecureViewerProcessGroupName]));
  end
  else
  begin
    Log(Format('NetLocalGroupDel() failed. nResult: %d', [nResult]));
    if (nResult AND ERROR_ACCESS_DENIED = ERROR_ACCESS_DENIED) then
    begin
      Log('  ERROR_ACCESS_DENIED');
    end;
    if (nResult AND NERR_InvalidComputer = NERR_InvalidComputer) then
    begin
      Log('  NERR_InvalidComputer');
    end;
    if (nResult AND NERR_NotPrimary = NERR_NotPrimary) then
    begin
      Log('  NERR_NotPrimary');
    end;
    if (nResult AND NERR_GroupNotFound = NERR_GroupNotFound) then
    begin
      Log('  NERR_GroupNotFound');
    end;
    if (nResult AND ERROR_NO_SUCH_ALIAS = ERROR_NO_SUCH_ALIAS) then
    begin
      Log('  ERROR_NO_SUCH_ALIAS');
    end;
  end;
end;

function SDGetSecureViewerProcessGroupName: string;
begin
  Result := FSecureViewerProcessGroupName;
end;

function SDGetSecureViewerProcessGroupSID: PSID;
var
  // pSecureViewerProcessGroupSID: Pointer;
  cbSid: Cardinal;
  ReferencedDomainName: PChar;
  cchReferencedDomainName: Cardinal;
  peUse: Cardinal;
  pStringSID: PChar;
begin
  Log('SDGetSecureViewerProcessGroupSID()');

  cbSid := 0;
  cchReferencedDomainName := 0;
  LookupAccountName(nil, PChar(FSecureViewerProcessGroupName), nil, cbSid, nil,
    cchReferencedDomainName, peUse);
  GetMem(Result, cbSid);
  GetMem(ReferencedDomainName, cchReferencedDomainName);

  if LookupAccountName(nil, PChar(FSecureViewerProcessGroupName), Result, cbSid,
    ReferencedDomainName, cchReferencedDomainName, peUse) then
  begin
    Log(Format('LookupAccountName(%s) succeeded.', [FSecureViewerProcessGroupName]));
    if ConvertSidToStringSid(Result, pStringSID) then
    begin
      Log(Format('  StringSID: %s', [StrPas(pStringSID)]));
    end;
  end
  else
  begin
    Log(Format('LookupAccountName(%s) failed: %s', [FSecureViewerProcessGroupName,
      SysErrorMessage(GetLastError)]));
  end;
end;

function SDCreateSecureDesktop(const ADesktopName: String): THandle;
const
  // WinNT.h
  SECURITY_BUILTIN_DOMAIN_RID  = $00000020;
  DOMAIN_ALIAS_RID_ADMINS = $00000220;
var
  // pEveryoneSID: Pointer;
  pAdministratorsSID: Pointer;
  pLocalSystemSID: Pointer;
  pSecureViewerProcessGroupSID: Pointer;
  // cbSid: Cardinal;
  // ReferencedDomainName: PChar;
  // cchReferencedDomainName: Cardinal;
  // peUse: Cardinal;
  // pStringSID: PChar;
  ea: array [0 .. 2] of EXPLICIT_ACCESS;
  dwResult: DWORD;
  NewACL: PACL;
  pSD: PSecurityDescriptor;
  lpsa: TSecurityAttributes;
begin
  Log(Format('SDCreateSecureDesktop("%s")', [ADesktopName]));

  Result := 0;

  pSecureViewerProcessGroupSID := SDGetSecureViewerProcessGroupSID;

  if ((Windows.AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 2, SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, pAdministratorsSID)) and
    (Windows.AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0,
    0, 0, 0, 0, pLocalSystemSID)) and (pSecureViewerProcessGroupSID <> nil)) then
  begin
    Log('AllocateAndInitializeSid(BUILTIN\Administrators) succeeded.');
    Log('AllocateAndInitializeSid(BUILTIN\SYSTEM) succeeded.');

    ea[0].grfAccessPermissions := _DELETE or DESKTOP_ENUMERATE or READ_CONTROL or WRITE_DAC or
      WRITE_OWNER;
    ea[0].grfAccessMode := SET_ACCESS;
    ea[0].grfInheritance := NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm := TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType := TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName := PChar(pAdministratorsSID);

    ea[1].grfAccessPermissions := GENERIC_ALL;
    ea[1].grfAccessMode := SET_ACCESS;
    ea[1].grfInheritance := NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm := TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType := TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName := PChar(pLocalSystemSID);

    ea[2].grfAccessPermissions := DESKTOP_READOBJECTS or DESKTOP_CREATEWINDOW or
      DESKTOP_CREATEMENU or DESKTOP_HOOKCONTROL or DESKTOP_JOURNALRECORD or
      DESKTOP_JOURNALPLAYBACK or DESKTOP_ENUMERATE or DESKTOP_WRITEOBJECTS;
    ea[2].grfAccessMode := SET_ACCESS;
    ea[2].grfInheritance := NO_INHERITANCE;
    ea[2].Trustee.TrusteeForm := TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType := TRUSTEE_IS_GROUP;
    ea[2].Trustee.ptstrName := pSecureViewerProcessGroupSID;

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
            lpsa.nLength := SizeOf(TSecurityAttributes);
            lpsa.lpSecurityDescriptor := pSD;
            lpsa.bInheritHandle := false;

            Result := CreateDesktop(PChar(SecureViewerDesktopName), nil, nil, 0,
              DESKTOP_CREATEMENU OR DESKTOP_CREATEWINDOW OR DESKTOP_ENUMERATE OR
              DESKTOP_HOOKCONTROL OR DESKTOP_JOURNALPLAYBACK OR DESKTOP_JOURNALRECORD OR
              DESKTOP_READOBJECTS OR DESKTOP_SWITCHDESKTOP OR DESKTOP_WRITEOBJECTS OR
              READ_CONTROL OR WRITE_DAC or WRITE_OWNER, @lpsa);
            if (Result <> 0) then
            begin
              Log(Format('CreateDesktop(%s) succeeded with handle: %d', [SecureViewerDesktopName,
                Result]));

              dwResult := SetSecurityInfo(Result, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, nil,
                nil, NewACL, nil);
              if (dwResult = ERROR_SUCCESS) then
              begin
                Log('SetSecurityInfo() succeeded.');
              end
              else
              begin
                Log(Format('SetSecurityInfo() failed: %s', [SysErrorMessage(GetLastError)]));
              end;
            end
            else
            begin
              Log(Format('CreateDesktop(%s) failed: %s', [SecureViewerDesktopName,
                SysErrorMessage(GetLastError)]));
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
        Log('GetMem() failed.');
      end;
      // if (LocalFree(NewACL) <> nil) then
      // begin
      // Log(Format('LocalFree() failed: %s', [SysErrorMessage(GetLastError)]));
      // end;
    end
    else
    begin
      Log(Format('SetEntriesInAcl() failed with %d: %s', [dwResult, SysErrorMessage(dwResult)]));
    end;

    // FreeSid(pEveryoneSID)
  end
  else
  begin
    // Log(Format('AllocateAndInitializeSid() failed: %s', [SysErrorMessage(GetLastError)]));
    Log(Format('Retrieval of SIDs failed: %s', [SysErrorMessage(GetLastError)]));
  end;

  // if InitializeAcl(@DACL, SizeOf(DACL), ACL_REVISION) then
  // begin
  // Log('InitializeAcl() succeeded.');
  // if AddAccessAllowedAce(@DACL, ACL_REVISION,
  // DESKTOP_CREATEMENU OR DESKTOP_CREATEWINDOW OR DESKTOP_ENUMERATE OR DESKTOP_HOOKCONTROL OR
  // DESKTOP_JOURNALPLAYBACK OR DESKTOP_JOURNALRECORD OR DESKTOP_READOBJECTS OR
  // DESKTOP_SWITCHDESKTOP OR DESKTOP_WRITEOBJECTS OR STANDARD_RIGHTS_REQUIRED,
  // ASID) then
end;

function SDClearSecureDesktop(const ADesktopName: string): Boolean;
var
  pLocalSystemSID: Pointer;
  ea: array [0 .. 0] of EXPLICIT_ACCESS;
  dwResult: DWORD;
  NewACL: PACL;
  hSecureViewerDesktop: THandle;
begin
  Result := false;
  Log(Format('SDClearSecureDesktop("%s")', [ADesktopName]));

  // Remove ACEs from desktop, only allow SYSTEM
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

      hSecureViewerDesktop := OpenDesktop(PChar(SecureViewerDesktopName), 0, false, WRITE_DAC or WRITE_OWNER);
      if (hSecureViewerDesktop <> 0) then
      begin
        Log(Format('OpenDesktop(%s) succeeded with handle: %d', [SecureViewerDesktopName,
          hSecureViewerDesktop]));

        dwResult := SetSecurityInfo(hSecureViewerDesktop, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, nil,
          nil, NewACL, nil);
        if (dwResult = ERROR_SUCCESS) then
        begin
          Log('SetSecurityInfo() succeeded.');
        end
        else
        begin
          Log(Format('SetSecurityInfo() failed: %s', [SysErrorMessage(GetLastError)]));
        end;
      end
      else
      begin
        Log(Format('OpenDesktop(%s) failed: %s', [SecureViewerDesktopName,
          SysErrorMessage(GetLastError)]));
      end;

      if (LocalFree(Cardinal(NewACL)) = 0) then
      begin
        Log('LocalFree(NewACL) succeeded.');
      end
      else
      begin
        Log(Format('LocalFree() failed: %s', [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('SetEntriesInAcl() failed with %d: %s', [dwResult, SysErrorMessage(dwResult)]));
    end;

    if (FreeSid(pLocalSystemSID) = nil) then
    begin
      Log('FreeSid(pLocalSystemSID) succeeded.');
    end
    else
    begin
      Log(Format('FreeSid(pLocalSystemSID) failed: %s', [SysErrorMessage(GetLastError)]));
    end;
  end
  else
  begin
    Log(Format('AllocateAndInitializeSid() failed: %s', [SysErrorMessage(GetLastError)]));
  end;

  // Remove secure viewer process group (i.e. capability)
  // Kill all threads associated with the secure desktop
  // Create new group
  // Set new ACE for the new group
end;

function SDCreateProcessWithTokenOnDesktop(const AModuleName: string; const ACommandLine: string;
  const AToken: THandle; const ADesktopName: string): Boolean;
var
  SI: Windows.TStartupInfo;
  NewProcessInformation: Windows.TProcessInformation;
  szCommandLine: PChar;
begin
  ZeroMemory(@SI, SizeOf(SI));
  SI.cb := SizeOf(SI);
  SI.lpDesktop := PChar(ADesktopName);
  szCommandLine := PChar('"' + AModuleName + '" ' + ACommandLine);
  Result := Windows.CreateProcessAsUser(AToken, PChar(AModuleName), szCommandLine, nil,
    // <- process attributes
    nil, // <- thread attributes
    false, 0, nil, nil, SI, NewProcessInformation);
  if Result then
  begin
    Log(Format('CreateProcessAsUser(%s:"%s") succeeded.', [ADesktopName, AModuleName]));
  end
  else
  begin
    Log(Format('CreateProcessAsUser() failed. LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDCreateProcessOnDesktop(const AModuleName: string; const ACommandLine: string;
  const ADesktopName: string): Boolean;
type
  _UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    // Buffer: PWSTR;
    Buffer: Pointer;
  end;

  UNICODE_STRING = _UNICODE_STRING;
  PUNICODE_STRING = ^UNICODE_STRING;
  TUnicodeString = UNICODE_STRING;
  //PUnicodeString = PUNICODE_STRING;

  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;

  _OBJECT_ATTRIBUTES = record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: ULONG;
    SecurityDescriptor: PVOID; // Points to type SECURITY_DESCRIPTOR
    SecurityQualityOfService: PVOID; // Points to type SECURITY_QUALITY_OF_SERVICE
  end;

  OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
  TObjectAttributes = OBJECT_ATTRIBUTES;
  PObjectAttributes = POBJECT_ATTRIBUTES;
var
  UserSessionId: Cardinal;
  AllProcesses: TProcesses;
  cProcessIndex: Cardinal;
  hUserDesktopProcessToken: THandle;
  SecurityQualityOfService: Windows.TSecurityQualityOfService;
  ObjectAttributes: TObjectAttributes;
  cReturnLength: Cardinal;
  UserDesktopProcessTokenStatistics: Windows.PTokenStatistics;
  AuthenticationId: Windows.TLUID;
  ExpirationTime: LARGE_INTEGER;
  User: Windows.PTokenUser;
  // pLocalSystemSID: Pointer;
  pSecureViewerProcessGroupSID: Pointer;
  Groups: Windows.PTokenGroups;
  Privileges: Windows.PTokenPrivileges;
  Owner: Windows.PTokenOwner;
  PrimaryGroup: Windows.PTokenPrimaryGroup;
  DefaultDacl: Windows.PTokenDefaultDacl;
  Source: Windows.PTokenSource;
  hSecureViewerGroupEnabledToken: THandle;
  cStatus: Cardinal;
begin
  Result := false;
  UserSessionId := WTSGetActiveConsoleSessionId;
  SDEnumerateProcessesSilently(AllProcesses);
  cProcessIndex := 0;
  while ((cProcessIndex < AllProcesses.ProcessCount) and
    (not((AllProcesses.Processes[cProcessIndex].FileName = 'bds.exe') and
    (AllProcesses.Processes[cProcessIndex].SessionID = UserSessionId)))) do
  begin
    // Log(Format('Session %d  PID %.5d  %s', [AllProcesses.Processes[nProcessIndex].SessionID, AllProcesses.Processes[nProcessIndex].PID, AllProcesses.Processes[nProcessIndex].FileName]));
    cProcessIndex := cProcessIndex + 1;
  end;
  Log(Format('Session %d  PID %.5d  %s', [AllProcesses.Processes[cProcessIndex].SessionID,
    AllProcesses.Processes[cProcessIndex].PID, AllProcesses.Processes[cProcessIndex].FileName]));
  if OpenProcessToken(OpenProcess(PROCESS_QUERY_INFORMATION, false,
    AllProcesses.Processes[cProcessIndex].PID), TOKEN_ALL_ACCESS, hUserDesktopProcessToken) then
  begin
    Log('Token for bds.exe');
    Log('OpenProcessToken() succeeded.');

    // Add group to token
    if SDAcquireTCBPrivilege then
    begin
      Log('SDAcquireTCBPrivilege() succeeded.');
      SecurityQualityOfService.Length := SizeOf(SecurityQualityOfService);
      SecurityQualityOfService.ImpersonationLevel := Windows.SecurityImpersonation;
      SecurityQualityOfService.ContextTrackingMode := SECURITY_STATIC_TRACKING;
      SecurityQualityOfService.EffectiveOnly := false;
      ObjectAttributes.Length := SizeOf(ObjectAttributes);
      ObjectAttributes.SecurityQualityOfService := @SecurityQualityOfService;

      // AuthenticationId := ProcessToken.GetTokenStatistics.AuthenticationId;
      // ExpirationTime := ProcessToken.GetTokenStatistics.ExpirationTime;
      Windows.GetTokenInformation(hUserDesktopProcessToken, Windows.TokenStatistics, nil, 0,
        cReturnLength);
      GetMem(UserDesktopProcessTokenStatistics, cReturnLength);
      if GetTokenInformation(hUserDesktopProcessToken, TokenStatistics,
        UserDesktopProcessTokenStatistics, cReturnLength, cReturnLength) then
      begin
        AuthenticationId := UserDesktopProcessTokenStatistics^.AuthenticationId;
        ExpirationTime := UserDesktopProcessTokenStatistics^.ExpirationTime;
      end
      else
      begin
        Log(Format('GetTokenInformation(TokenStatistics) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;

      // FillChar(User.User, SizeOf(User.User), 0);
      // User.User.Sid := ProcessToken.GetTokenUser.CreateCopyOfSID;
      GetTokenInformation(hUserDesktopProcessToken, TokenUser, nil, 0, cReturnLength);
      GetMem(User, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenUser, User, cReturnLength,
        cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenUser) failed: %s', [SysErrorMessage(GetLastError)]));
      end;

      Log('TokenGroups');
      GetTokenInformation(hUserDesktopProcessToken, TokenGroups, nil, 0, cReturnLength);
      Log(Format('dwReturnLength: %d  SizeOf(Windows.SID_AND_ATTRIBUTES): %d',
        [cReturnLength, SizeOf(Windows.SID_AND_ATTRIBUTES)]));
      // GetMem(Groups, dwReturnLength + SizeOf(Windows.SID_AND_ATTRIBUTES));
      GetMem(Groups, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenGroups, Groups, cReturnLength,
        cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenGroups) failed: %s', [SysErrorMessage(GetLastError)]));
      end;
      Log(Format('Groups^.GroupCount: %d', [Groups^.GroupCount]));

      pSecureViewerProcessGroupSID := SDGetSecureViewerProcessGroupSID;
      if (pSecureViewerProcessGroupSID <> nil) then
      // if (Windows.AllocateAndInitializeSid(SECURITY_NT_AUTHORITY, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, pLocalSystemSID)) then
      begin
        Log('Adding group to token');
        // Groups := SDAddGroupToToken(hUserDesktopProcessToken, pLocalSystemSID);
        Groups := SDAddGroupToToken(hUserDesktopProcessToken, pSecureViewerProcessGroupSID);
        Log('Added group to token');
      end;

      // Privileges := ProcessToken.GetTokenPrivileges.Create_PTOKEN_PRIVILEGES;
      GetTokenInformation(hUserDesktopProcessToken, TokenPrivileges, nil, 0, cReturnLength);
      GetMem(Privileges, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenPrivileges, Privileges,
        cReturnLength, cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenPrivileges) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;

      // Owner.Owner := ProcessToken.GetTokenOwner.CreateCopyOfSID;
      GetTokenInformation(hUserDesktopProcessToken, TokenOwner, nil, 0, cReturnLength);
      GetMem(Owner, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenOwner, Owner, cReturnLength,
        cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenOwner) failed: %s', [SysErrorMessage(GetLastError)]));
      end;

      // PrimaryGroup.PrimaryGroup := ProcessToken.GetPrimaryGroup.CreateCopyOfSID;
      GetTokenInformation(hUserDesktopProcessToken, TokenPrimaryGroup, nil, 0, cReturnLength);
      GetMem(PrimaryGroup, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenPrimaryGroup, PrimaryGroup,
        cReturnLength, cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenPrimaryGroup) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;

      // DefaultDacl.DefaultDacl := ProcessToken.GetTokenDefaultDacl.Create_PACL;
      GetTokenInformation(hUserDesktopProcessToken, TokenDefaultDacl, nil, 0, cReturnLength);
      GetMem(DefaultDacl, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenDefaultDacl, DefaultDacl,
        cReturnLength, cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenDefaultDacl) failed: %s',
          [SysErrorMessage(GetLastError)]));
      end;

      // Source.SourceName := 'SecDesk';
      // Source.SourceIdentifier.LowPart := 0;
      // Source.SourceIdentifier.HighPart := 0;
      GetTokenInformation(hUserDesktopProcessToken, TokenSource, nil, 0, cReturnLength);
      GetMem(Source, cReturnLength);
      if (not GetTokenInformation(hUserDesktopProcessToken, TokenSource, Source, cReturnLength,
        cReturnLength)) then
      begin
        Log(Format('GetTokenInformation(TokenSource) failed: %s', [SysErrorMessage(GetLastError)]));
      end;

      hSecureViewerGroupEnabledToken := 0;
      cStatus := ZwCreateToken(@hSecureViewerGroupEnabledToken, TOKEN_ALL_ACCESS, @ObjectAttributes,
        Windows.TokenPrimary, @AuthenticationId, @ExpirationTime, User, Groups, Privileges, Owner,
        PrimaryGroup, DefaultDacl, Source);
      Log(Format('ZwCreateToken(): %d  LastError: %s', [cStatus, SysErrorMessage(cStatus)]));

      Log(Format('Session (hSecureViewerGroupEnabledToken): %d',
        [GetTokenSessionId(hSecureViewerGroupEnabledToken)]));
      if Windows.DuplicateTokenEx(hSecureViewerGroupEnabledToken, Windows.MAXIMUM_ALLOWED, nil,
        Windows.SecurityImpersonation, Windows.TokenPrimary, hSecureViewerGroupEnabledToken) then
      begin
        Log('DuplicateToken() succeeded.');
      end
      else
      begin
        Log('DuplicateToken() failed.');
      end;
      Log(Format('Session (hSecureViewerGroupEnabledToken): %d',
        [GetTokenSessionId(hSecureViewerGroupEnabledToken)]));

      Log(Format('Session (hUserDesktopProcessToken): %d',
        [GetTokenSessionId(hUserDesktopProcessToken)]));
      UserSessionId := GetTokenSessionId(hUserDesktopProcessToken);
      SDDumpThreadPrivileges(GetCurrentThread);
      if SetTokenInformation(hSecureViewerGroupEnabledToken, TokenSessionId, @UserSessionId,
        SizeOf(UserSessionId)) then
      begin
        Log('SetTokenInformation() succeeded.');
      end
      else
      begin
        Log(Format('SetTokenInformation() failed: %s', [SysErrorMessage(GetLastError)]));
      end;
      Log(Format('Session (hSecureViewerGroupEnabledToken): %d',
        [GetTokenSessionId(hSecureViewerGroupEnabledToken)]));
      GetTokenUser(hSecureViewerGroupEnabledToken);
      GetTokenGroups(hSecureViewerGroupEnabledToken);

      Result := SDCreateProcessWithTokenOnDesktop(AModuleName, ACommandLine,
        hSecureViewerGroupEnabledToken, ADesktopName);
      SDReleaseTCBPrivilege;
    end
    else
    begin
      Log('SDAcquireTCBPrivilege() failed.');
    end;
  end;
end;

function SDCreateProcess(const AModuleName: string; const ACommandLine: string): Boolean;
begin
  Result := SDCreateProcessOnDesktop(AModuleName, ACommandLine, SecureViewerDesktopName);
end;

function SDAcquireTCBPrivilege: Boolean;
const
  // WinNT.h
  SE_CREATE_TOKEN_NAME = 'SeCreateTokenPrivilege';
var
  // GroupSid: PSID;
  // cbSid: Cardinal;
  // ReferencedDomainName: PChar;
  // cchReferencedDomainName: Cardinal;
  // peUse: Cardinal;
  nPrivilegedProcessId: DWORD;
  hPrivilegedProcess: THandle;
  hPrivilegedToken: THandle;
  // RequiredPrivileges: TPrivilegeSet;
  // pfResult: LongBool;
  EnablePrivileges: Windows.TTokenPrivileges;
  PreviousPrivileges: Windows.TTokenPrivileges;
  nReturnLength: Cardinal;
  // hNewToken: THandle;
  // nStatus: Cardinal;
  // SI: Windows.TStartupInfo;
  // PI: Windows.TProcessInformation;

  // SecurityQualityOfService: TSecurityQualityOfService;
  // ObjectAttributes: TObjectAttributes;
  // AuthenticationId: TLUID;
  // ExpirationTime: LARGE_INTEGER;
  // User:  TTokenUser;
  // Groups: JwaWindows.PTokenGroups;
  // Privileges: PTokenPrivileges;
  // Owner: TTokenOwner;
  // PrimaryGroup: TTokenPrimaryGroup;
  // DefaultDacl: TTokenDefaultDacl;
  // Source: TTokenSource;
  // SessionID: DWORD;
begin
  Log('SDAcquireTCBPrivilege()');
  Result := false;
  nPrivilegedProcessId := SDFindPIDWithPrivilege(SE_CREATE_TOKEN_NAME);
  if (nPrivilegedProcessId <> 0) then
  begin
    hPrivilegedToken := 0;
    hPrivilegedProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, false,
      nPrivilegedProcessId);
    if (hPrivilegedProcess <> 0) then
    begin
      if OpenProcessToken(hPrivilegedProcess, TOKEN_ALL_ACCESS, hPrivilegedToken) then
      begin
        Log(Format('OpenProcessToken(hPrivilegedProcess) succeeded.', []));
        if (NOT IsPrivilegeEnabled(hPrivilegedToken, SE_CREATE_TOKEN_NAME)) then
        begin
          EnablePrivileges.PrivilegeCount := 1;
          Windows.LookupPrivilegeValue(nil, SE_CREATE_TOKEN_NAME,
            EnablePrivileges.Privileges[0].Luid);
          EnablePrivileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
          PreviousPrivileges := EnablePrivileges;
          nReturnLength := 0;
          if Windows.AdjustTokenPrivileges(hPrivilegedToken, false, EnablePrivileges,
            SizeOf(PreviousPrivileges), PreviousPrivileges, nReturnLength) then
          begin
            Log(Format('AdjustTokenPrivileges() succeeded.', []));
          end
          else
          begin
            Log(Format('AdjustTokenPrivileges() failed. LastError: %s',
              [SysErrorMessage(GetLastError)]));
          end;
        end;
      end
      else
      begin
        Log(Format('OpenProcessToken(hPrivilegedProcess) failed. LastError: %s',
          [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('OpenProcess(nPrivilegedProcessId) failed. LastError: %s',
        [SysErrorMessage(GetLastError)]));
    end;

    if ((hPrivilegedToken <> 0) and IsPrivilegeEnabled(hPrivilegedToken, SE_CREATE_TOKEN_NAME)) then
    begin
      // Debug('Dumping privileges before impersonation');
      // SDDumpThreadPrivileges(GetCurrentThread);
      if ImpersonateLoggedOnUser(hPrivilegedToken) then
      begin
        Log(Format('ImpersonateLoggedOnUser() succeeded.', []));
        // Log('Dumping privileges after impersonation');
        // SDDumpThreadPrivileges(GetCurrentThread);
        Result := true;
      end
      else
      begin
        Log(Format('ImpersonateLoggedOnUser() failed. LastError: %s',
          [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('No token obtained. LastError: %s', [SysErrorMessage(GetLastError)]));
    end;
  end
  else
  begin
    Log(Format('No privileged process found.', []));
  end;
end;

function SDReleaseTCBPrivilege: Boolean;
begin
  Result := RevertToSelf;
  if Result then
  begin
    Log(Format('RevertToSelf() succeeded.', []));
    // SDDumpThreadPrivileges(GetCurrentThread);
  end
  else
  begin
    Log(Format('RevertToSelf() failed. LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function SDAddGroupToToken(const AToken: THandle; const ASID: Pointer): Windows.PTokenGroups;
var
  Groups: Windows.PTokenGroups;
  cReturnLength: Cardinal;
  ModifiedGroups: Windows.PTokenGroups;
  nGroupIndex: Integer;

begin
  GetTokenInformation(AToken, TokenGroups, nil, 0, cReturnLength);
  GetMem(Groups, cReturnLength);
  if (GetTokenInformation(AToken, TokenGroups, Groups, cReturnLength, cReturnLength)) then
  begin
    Log(Format('Groups^.GroupCount: %d', [Groups^.GroupCount]));
    GetMem(ModifiedGroups, SizeOf(Cardinal) + (Groups^.GroupCount + 1) *
      SizeOf(Windows.SID_AND_ATTRIBUTES));
    for nGroupIndex := 0 to (Groups^.GroupCount - 1) do
    begin
      ModifiedGroups^.Groups[nGroupIndex].Sid := Groups^.Groups[nGroupIndex].Sid;
      ModifiedGroups^.Groups[nGroupIndex].Attributes := Groups^.Groups[nGroupIndex].Attributes;
    end;
    ModifiedGroups^.GroupCount := Groups^.GroupCount + 1;
    ModifiedGroups^.Groups[ModifiedGroups^.GroupCount - 1].Sid := ASID;
    ModifiedGroups^.Groups[ModifiedGroups^.GroupCount - 1].Attributes := 7;

    Result := ModifiedGroups;
    // ProcessToken.GetTokenGroups.Create_PTOKEN_GROUPS
  end
  else
  begin
    Log(Format('GetTokenInformation(TokenGroups) failed: %s', [SysErrorMessage(GetLastError)]));
    Result := nil;
  end;
end;

end.
