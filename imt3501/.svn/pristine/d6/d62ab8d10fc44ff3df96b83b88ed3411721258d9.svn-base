unit SDInfoSecurity;

interface

uses
  SDInfoProcesses,
  Windows,
  JwaWindows;

// Move to SDInfoProcesses or SDModifiedTokens once dependence on Jwa* is removed
function SDDumpProcessToken(var AProcessData: TProcessData): Boolean;
function SDDumpACL(const AACL: Windows.PACL): Boolean;
function SDAddGroupToTokenGroups(const Groups: JwaWindows.PTokenGroups; const AGroupSid: PSID)
  : JwaWindows.PTokenGroups;
function AddGroupToToken(var AProcessData: TProcessData): Boolean;

function SDDumpSecurityInfo(const ASecurityDescriptor: Windows.PSecurityDescriptor): Boolean;

implementation

uses
  SDCommon,
  SDModifiedTokens,
  SysUtils,
  JwsclSid,
  JwsclToken,
  JwsclTypes,
  JwsclACL;

function AceTypeToText(const AAceType: TJwAceType): string;
begin
  case AAceType of
    actAudit:
      Result := 'actAudit';
    actAuditCallback:
      Result := 'actAuditCallback';
    actAuditObject:
      Result := 'actAuditObject';
    actAuditCallbackObject:
      Result := 'actAuditCallbackObject';

    actMandatory:
      Result := 'actMandatory';

    actAllow:
      Result := 'actAllow';
    actAllowCallback:
      Result := 'actAllowCallback';
    actAllowObject:
      Result := 'actAllowObject';
    actAllowCallbackObject:
      Result := 'actAllowCallbackObject';

    actDeny:
      Result := 'actDeny';
    actDenyCallback:
      Result := 'actDenyCallback';
    actDenyObject:
      Result := 'actDenyObject';
    actDenyCallbackObject:
      Result := 'actDenyCallbackObject';

    actUnknown:
      Result := 'actUnknown';
  else
    Result := '';
  end;
end;

function SDDumpProcessToken(var AProcessData: TProcessData): Boolean;
var
  hProcess: THandle;
  hToken: THandle;
  ProcessToken: TJwSecurityToken;
  nGroupIndex: Integer;
begin
  Log(Format('SDDumpProcessToken(PID: %d %s)', [AProcessData.PID, AProcessData.FileName]));
  Result := false;
  hProcess := OpenProcess(PROCESS_QUERY_INFORMATION OR PROCESS_VM_READ, false, AProcessData.PID);
  if (hProcess <> 0) then
  begin
    if OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, hToken) then
    begin
      Log(Format('OpenProcessToken() succeeded', []));
      try
        ProcessToken := TJwSecurityToken.CreateDuplicateExistingToken(hToken, TOKEN_ALL_ACCESS);
        // Log(Format('ProcessToken.GetUserName: %s', [ProcessToken.GetTokenUserName]));
        Log(Format('GetTokenUser: %s', [GetTokenUser(hToken)]));

        for nGroupIndex := 0 to ProcessToken.GetTokenGroups.Count - 1 do
        begin
          try
            Log(Format('  Group %.2d: %s', [nGroupIndex,
              GetSidUserName(ProcessToken.GetTokenGroups.Items[nGroupIndex].SID)]));
          except
            on E: Exception do
            begin
              Log(E.Message);
            end;
          end;
        end;
        // Log(Format('GetTokenGroups: %s', [GetTokenGroups(hToken)]));

        AProcessData.SessionID := GetTokenSessionId(hToken);
        Log(Format('GetTokenSessionId: %d', [AProcessData.SessionID]));

        // ProcessToken := TJwSecurityToken.CreateNewToken();
        Log(Format('', []));

      except
        Log(Format('  LastError: %s', [SysErrorMessage(GetLastError)]));
      end;
      Result := true;
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

function SDDumpACL(const AACL: Windows.PACL): Boolean;
var
  nACEIndex: Integer;
  DesktopDACL: TJwDAccessControlList;
begin
  DesktopDACL := TJwDAccessControlList.Create(JwaWindows.PACL(AACL));
  for nACEIndex := 0 to DesktopDACL.Count - 1 do
  begin
    Log(Format('ACE %d', [nACEIndex]));
    Log(Format('Account name: %s (SID: %s)', [SDLookupAccountBySID(DesktopDACL[nACEIndex].SID.SID),
      DesktopDACL[nACEIndex].SID.StringSID]));
    Log(Format('ACE type: %s', [AceTypeToText(DesktopDACL[nACEIndex].AceType)]));
    // Log(Format('ACE: %s', [DesktopDACL[nACEIndex].GetText]));
    Log(Format('Access mask: %s', [IntToHex(DesktopDACL[nACEIndex].AccessMask, 8)]));
    SDDumpAccessMask(DesktopDACL[nACEIndex].AccessMask);
  end;
  Result := true;
end;

function SDAddGroupToTokenGroups(const Groups: JwaWindows.PTokenGroups; const AGroupSid: PSID)
  : JwaWindows.PTokenGroups;
var
  nGroupIndex: Integer;
begin
  Log(Format('SDAddGroupToToken(Groups: %p)', [Groups]));

  GetMem(Result, SizeOf(Groups^.GroupCount) + (Groups^.GroupCount + 1) * SizeOf(TSIDAndAttributes));
  Result.GroupCount := Groups^.GroupCount + 1;
  for nGroupIndex := 0 to (Groups^.GroupCount - 1) do
  begin
    Result.Groups[nGroupIndex].SID := Groups^.Groups[nGroupIndex].SID;
    Result.Groups[nGroupIndex].Attributes := Groups^.Groups[nGroupIndex].Attributes;
  end;
  Result.Groups[Result.GroupCount - 1].SID := AGroupSid;
  Result.Groups[Result.GroupCount - 1].Attributes := SE_GROUP_ENABLED OR
    SE_GROUP_ENABLED_BY_DEFAULT OR SE_GROUP_MANDATORY;
end;

function AddGroupToToken(var AProcessData: TProcessData): Boolean;
var
  ProcessToken: TJwSecurityToken;
  GroupSid: PSID;
  cbSid: Cardinal;
  ReferencedDomainName: PChar;
  cchReferencedDomainName: Cardinal;
  peUse: Cardinal;
  nPrivilegedProcessId: DWORD;
  hPrivilegedProcess: THandle;
  hPrivilegedToken: THandle;
  // RequiredPrivileges: TPrivilegeSet;
  // pfResult: LongBool;
  EnablePrivileges: Windows.TTokenPrivileges;
  PreviousPrivileges: Windows.TTokenPrivileges;
  nReturnLength: Cardinal;
  hNewToken: THandle;
  nStatus: Cardinal;

  SecurityQualityOfService: TSecurityQualityOfService;
  ObjectAttributes: TObjectAttributes;
  AuthenticationId: TLUID;
  ExpirationTime: LARGE_INTEGER;
  User: TTokenUser;
  Groups: JwaWindows.PTokenGroups;
  Privileges: PTokenPrivileges;
  Owner: TTokenOwner;
  PrimaryGroup: TTokenPrimaryGroup;
  DefaultDacl: TTokenDefaultDacl;
  Source: TTokenSource;
  SessionID: DWORD;
begin
  Log(Format('AddGroupToToken(PID: %d) %s', [AProcessData.PID, AProcessData.FileName]));
  Result := false;
  if (AProcessData.FileName = 'bds.exe') then
  begin
    try
      ProcessToken := TJwSecurityToken.CreateTokenByProcessId(AProcessData.PID, MAXIMUM_ALLOWED);
      Log(Format('ProcessToken.GetUserName: %s', [ProcessToken.GetTokenUserName]));
      Log(Format('ProcessToken.TokenHandle: %d', [ProcessToken.TokenHandle]));

      GroupSid := nil;
      cbSid := 0;
      ReferencedDomainName := nil;
      cchReferencedDomainName := 0;
      LookupAccountName(nil, PChar(SDGetSecureViewerProcessGroupName), GroupSid, cbSid,
        ReferencedDomainName, cchReferencedDomainName, peUse);
      if (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
      begin
        GetMem(GroupSid, cbSid);
        GetMem(ReferencedDomainName, cchReferencedDomainName);
        if LookupAccountName(nil, PChar(SDGetSecureViewerProcessGroupName), GroupSid, cbSid,
          ReferencedDomainName, cchReferencedDomainName, peUse) then
        begin
          Log(Format('LookupAccountName() succeeded.', []));
          Log(Format('GetSidUserName(GroupSid): %s', [GetSidUserName(GroupSid)]));

          ProcessToken.TokenGroups.Add(TJwSecurityId.Create(GroupSid));
          Log(Format('Added group to token.', []));
          Log(Format('700 ProcessToken.TokenHandle: %d', [ProcessToken.TokenHandle]));

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
                    IsPrivilegeEnabled(hPrivilegedToken, SE_CREATE_TOKEN_NAME);
                  end
                  else
                  begin
                    Log(Format('AdjustTokenPrivileges() failed. LastError: %s',
                      [SysErrorMessage(GetLastError)]));
                    IsPrivilegeEnabled(hPrivilegedToken, SE_CREATE_TOKEN_NAME);
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

            if (hPrivilegedToken <> 0) then
            begin
              // Debug('Dumping privileges before impersonation');
              // SDDumpThreadPrivileges(GetCurrentThread);
              // if Windows.SetThreadToken(nil, hPrivilegedToken) then
              Log(Format('745 ProcessToken.TokenHandle: %d', [ProcessToken.TokenHandle]));
              if ImpersonateLoggedOnUser(hPrivilegedToken) then
              begin
                Log(Format('ImpersonateLoggedOnUser() succeeded.', []));
                Log('Dumping privileges after impersonation');
                SDDumpThreadPrivileges(GetCurrentThread);

                // Get token to be used as base (i.e. a token existing for the logged on user, not the LOCALSYSTEM token)
                // --- That token is captured already in ProcessToken at the very beginning of this method! ---
                // if DuplicateToken(hPrivilegedToken, SecurityImpersonation, hNewToken) then
                // if WTSQueryUserToken(1, hNewToken) then
                if true then
                begin
                  Log(Format('WTSQueryUserToken() succeeded.', []));

                  Log(Format('759 ProcessToken.TokenHandle: %d', [ProcessToken.TokenHandle]));
                  // ProcessToken.ConvertToPrimaryToken(0);
                  // hNewToken := ProcessToken.TokenHandle;

                  // Modify the token, then call ZwCreateToken to build a token to be used for the process to be displayed on the secure dsktop
                  SecurityQualityOfService.Length := SizeOf(SecurityQualityOfService);
                  SecurityQualityOfService.ImpersonationLevel := SecurityImpersonation;
                  SecurityQualityOfService.ContextTrackingMode := SECURITY_STATIC_TRACKING;
                  SecurityQualityOfService.EffectiveOnly := false;
                  ObjectAttributes.Length := SizeOf(ObjectAttributes);
                  ObjectAttributes.SecurityQualityOfService := @SecurityQualityOfService;
                  AuthenticationId := ProcessToken.GetTokenStatistics.AuthenticationId;
                  ExpirationTime := ProcessToken.GetTokenStatistics.ExpirationTime;
                  FillChar(User.User, SizeOf(User.User), 0);
                  User.User.SID := ProcessToken.GetTokenUser.CreateCopyOfSID;
                  Groups := SDAddGroupToTokenGroups
                    (ProcessToken.GetTokenGroups.Create_PTOKEN_GROUPS, GroupSid);
                  Privileges := ProcessToken.GetTokenPrivileges.Create_PTOKEN_PRIVILEGES;
                  Owner.Owner := ProcessToken.GetTokenOwner.CreateCopyOfSID;
                  PrimaryGroup.PrimaryGroup := ProcessToken.GetPrimaryGroup.CreateCopyOfSID;
                  DefaultDacl.DefaultDacl := ProcessToken.GetTokenDefaultDacl.Create_PACL;
                  Source.SourceName := 'SecDesk';
                  Source.SourceIdentifier.LowPart := 0;
                  Source.SourceIdentifier.HighPart := 0;

                  nStatus := JwaWindows.ZwCreateToken(@hNewToken, TOKEN_ALL_ACCESS,
                    @ObjectAttributes, TokenPrimary, @AuthenticationId, @ExpirationTime, @User,
                    Groups, Privileges, @Owner, @PrimaryGroup, @DefaultDacl, @Source);
                  Log(Format('ZwCreateToken: %d  LastError: %s',
                    [nStatus, SysErrorMessage(nStatus)]));

                  Log(Format('Session: %d', [GetTokenSessionId(hNewToken)]));
                  SessionID := GetTokenSessionId(ProcessToken.TokenHandle);
                  SetTokenInformation(hNewToken, TokenSessionId, @SessionID, SizeOf(SessionID));
                  Log(Format('Session: %d', [GetTokenSessionId(hNewToken)]));
                  GetTokenUser(hNewToken);
                  GetTokenGroups(hNewToken);

                  // Start two processes for testing: a) notepad.exe without added group, b) calc.exe with added group
                  // -> Adds a visual indicator for success when new desktop's ACL is modified/set

                  if SDCreateProcessWithTokenOnDesktop('C:\Windows\system32\calc.exe', '',
                    hNewToken, 'Default') then
                  // if SDCreateProcessWithTokenOnDesktop('C:\Projects\WinStaTest\tasklist64\tasklist64.exe', hNewToken, 'Default') then
                  begin
                    Log(Format('SDCreateProcessWithTokenOnDesktop() succeeded.', []));
                  end
                  else
                  begin
                    Log(Format('SDCreateProcessWithTokenOnDesktop() failed. LastError: %s',
                      [SysErrorMessage(GetLastError)]));
                  end;
                end
                else
                begin
                  Log(Format('DuplicateToken() failed. LastError: %s',
                    [SysErrorMessage(GetLastError)]));
                end;

                if RevertToSelf then
                begin
                  Log(Format('RevertToSelf() succeeded.', []));
                  SDDumpThreadPrivileges(GetCurrentThread);
                end
                else
                begin
                  Log(Format('RevertToSelf() failed. LastError: %s',
                    [SysErrorMessage(GetLastError)]));
                end;
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
      end;

      Log(Format('', []));

    except
      on E: Exception do
      begin
        Log(Format('  Exception: %s', [E.Message]));
        Log(Format('  LastError: %s', [SysErrorMessage(GetLastError)]));
      end;
    end;
    Result := true;
  end;
end;

function SDDumpSecurityInfo(const ASecurityDescriptor: Windows.PSecurityDescriptor): Boolean;
var
  pOwner: Windows.PSID;
  lpbOwnerDefaulted: LongBool;
  cbName: Cardinal;
  OwnerName: PChar;
  cbReferencedDomainName: Cardinal;
  ReferencedDomainName: PChar;
  peUse: Cardinal;
  lpbDACLPresent: LongBool;
  pDACL: Windows.PACL;
  lpbDACLDefaulted: LongBool;
begin
  Windows.GetSecurityDescriptorOwner(ASecurityDescriptor, pOwner, lpbOwnerDefaulted);

  cbName := 2048 + 1;
  GetMem(OwnerName, cbName);
  cbReferencedDomainName := 2048 + 1;
  GetMem(ReferencedDomainName, cbReferencedDomainName);
  if LookupAccountSid(nil, pOwner, OwnerName, cbName, ReferencedDomainName, cbReferencedDomainName,
    peUse) then
  begin
    Log(Format('LookupAccountSid() succeeded', []));
    Log(Format('Owner name: %s', [StrPas(OwnerName)]));
    Log(Format('Domain: %s', [StrPas(ReferencedDomainName)]));
  end
  else
  begin
    Log(Format('LookupAccountSid() failed. LastError: %s', [SysErrorMessage(GetLastError)]));
  end;

  Windows.GetSecurityDescriptorDacl(ASecurityDescriptor, lpbDACLPresent, pDACL, lpbDACLDefaulted);

  if lpbDACLPresent then
  begin
    Log(Format('GetSecurityDescriptorDacl() succeeded', []));
    Log(Format('ACECount: %d', [pDACL^.AceCount]));
    SDDumpACL(pDACL);
  end
  else
  begin
    Log(Format('GetSecurityDescriptorDacl() failed. LastError: %s',
      [SysErrorMessage(GetLastError)]));
  end;
  Result := true;
end;

end.
