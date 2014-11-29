unit SDSecureDisplaySvcUnit;

interface

uses
  Windows,
  SysUtils,
  SvcMgr,
  Classes,
  IdHTTPWebBrokerBridge,
  SDProtocol;

type
  TSDSecureDisplayService = class(TService)
    procedure ServiceExecute(Sender: TService);
    procedure ServiceAfterInstall(Sender: TService);
  private
    { Private declarations }
    FShouldTerminate: Boolean;
    FCurrentState: TSDPState;
    FCurrentApplicationId: Cardinal;
    FUserSessionManagerResponse: THandle;
    FUserSessionManagerCommands: THandle;
    FInvokerRequests: TIdHTTPWebBrokerBridge;
    function LaunchUserSessionManager(const ATargetSessionId: Cardinal): Boolean;
  public
    function GetServiceController: TServiceController; override;
    { Public declarations }
    procedure StartAsLocalSystemInSession(const AModuleName: string; const ASessionId: Cardinal;
      const ADesktopName: string);
  published
    property CurrentState: TSDPState read FCurrentState write FCurrentState;
    property CurrentApplicationId: Cardinal read FCurrentApplicationId write FCurrentApplicationId;
  end;

var
  SDSecureDisplayService: TSDSecureDisplayService;

implementation

{$R *.DFM}

uses
  ExtCtrls,
  Graphics,
  Registry,
  SDCommon,
  SDInfoProcesses,
  SDModifiedTokens;

procedure ServiceController(CtrlCode: DWord); stdcall;
begin
  SDSecureDisplayService.Controller(CtrlCode);
end;

function TSDSecureDisplayService.GetServiceController: TServiceController;
begin
  Result := ServiceController;
end;

function TSDSecureDisplayService.LaunchUserSessionManager(const ATargetSessionId: Cardinal)
  : Boolean;
var
  sMessage: string;
begin
  Result := false;
  if (SDCreateSecureMailslot(SecureViewerMailslotForBackgroundService,
    FUserSessionManagerResponse)) then
  begin
    Log('SDCreateSecureMailslot() succeeded.');

    StartAsLocalSystemInSession(ExtractFilePath(ParamStr(0)) + 'SDUserSessionManager.exe',
      ATargetSessionId, 'Winlogon');
    if SDReadFromMailslot(FUserSessionManagerResponse, sMessage, 5000) then
    begin
      Log(Format('Message from session %d: "%s"', [ATargetSessionId, sMessage]));
    end;

    if SDMessageMatches(sMessage, SDP_SUCCESS + SDP_READY) then
    begin
      if SDOpenMailslot(SecureViewerMailslotForUserSessionManager, FUserSessionManagerCommands) then
      begin
        Log('SDOpenMailslot() succeeded.');
        Result := true;
      end
      else
      begin
        Log(Format('SDOpenMailslot() failed: %s', [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('Unexpected message: "%s" (received) vs. "%s" (expected)',
        [sMessage, SDP_SUCCESS + SDP_READY]));
    end;
  end
  else
  begin
    Log(Format('SDCreateSecureMailslot() failed. LastError: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

procedure TSDSecureDisplayService.StartAsLocalSystemInSession(const AModuleName: string;
  const ASessionId: Cardinal; const ADesktopName: string);
var
  hServiceToken: THandle;
  hUserSessionManagerToken: THandle;
  SI: Windows.TStartupInfo;
  NewProcessInformation: Windows.TProcessInformation;
begin
  Log('StartAsLocalSystemInSession()');
  if Windows.ImpersonateSelf(Windows.SecurityImpersonation) then
  begin
    Log('ImpersonateSelf() succeeded.');
    if Windows.OpenThreadToken(Windows.GetCurrentThread, Windows.TOKEN_ALL_ACCESS, false,
      hServiceToken) then
    begin
      Log('OpenThreadToken() succeeded.');
      if Windows.DuplicateTokenEx(hServiceToken, Windows.MAXIMUM_ALLOWED, nil,
        Windows.SecurityImpersonation, Windows.TokenPrimary, hUserSessionManagerToken) then
      begin
        Log('DuplicateTokenEx() succeeded.');
        if Windows.SetTokenInformation(hUserSessionManagerToken, Windows.TokenSessionId,
          @ASessionId, SizeOf(DWord)) then
        begin
          Log('SetTokenInformation() succeeded.');
          ZeroMemory(@SI, SizeOf(SI));
          SI.cb := SizeOf(SI);
          SI.lpDesktop := PChar(ADesktopName);
          ZeroMemory(@NewProcessInformation, SizeOf(NewProcessInformation));

          if Windows.CreateProcessAsUser(hUserSessionManagerToken, PChar(AModuleName), nil, nil,
            // <- process attributes
            nil, // <- thread attributes
            false, 0, // <- creation flags
            nil, // <- environment
            nil, // <- current directory
            SI, NewProcessInformation) then
          begin
            Log(Format('CreateProcessAsUser(%s:%d:"%s") succeeded.',
              [ADesktopName, NewProcessInformation.dwProcessId, AModuleName]));
            CloseHandle(NewProcessInformation.hProcess);
            CloseHandle(NewProcessInformation.hThread);
          end
          else
          begin
            Log(Format('CreateProcessAsUser() failed. LastError: %s',
              [SysErrorMessage(GetLastError)]));
          end;
        end
        else
        begin
          Log(Format('SetTokenInformation() failed: %s', [SysErrorMessage(GetLastError)]));
        end;
        CloseHandle(hUserSessionManagerToken);
      end
      else
      begin
        Log(Format('DuplicateTokenEx() failed: %s', [SysErrorMessage(GetLastError)]));
      end;
      CloseHandle(hServiceToken);
    end
    else
    begin
      Log(Format('OpenThreadToken() failed: %s', [SysErrorMessage(GetLastError)]));
    end;
  end
  else
  begin
    Log(Format('ImpersonateSelf() failed: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

procedure TSDSecureDisplayService.ServiceAfterInstall(Sender: TService);
var
  Reg: TRegistry;
begin
  Reg := TRegistry.Create(KEY_READ or KEY_WRITE);
  try
    Reg.RootKey := HKEY_LOCAL_MACHINE;
    if Reg.OpenKey('\SYSTEM\CurrentControlSet\Services\' + Name, false) then
    begin
      Reg.WriteString('Description', 'The Secure Display Service allows secure communication ' +
        'between an application and the user.');
      Reg.CloseKey;
    end;
  finally
    Reg.Free;
  end;
end;

procedure TSDSecureDisplayService.ServiceExecute(Sender: TService);
var
  TargetSessionId: Cardinal;
  sResponse: string;
begin
  Log('Service started');
  FShouldTerminate := false;

  // if SDRetrieveWindowStationsAndDesktops then
  // begin
  // SDDumpWindowStationAndDesktopSecurityInformation;
  // end;

  // StartAsLocalSystemInSession(extractFilePath(ParamStr(0))+'\'+'SDDumpDesktopACL.exe', 0, 'Winsta0\Default');

  FCurrentState := sdpCreated;
  while ((not FShouldTerminate) and (not Self.Terminated)) do
  begin
    case FCurrentState of
      sdpCreated:
        begin
          Log('Entered sdpCreated state');
          FCurrentState := sdpQuit;
          TargetSessionId := WTSGetActiveConsoleSessionId;
          if LaunchUserSessionManager(TargetSessionId) then
          begin
            Log(Format('LaunchUserSessionManager(Session: %d) succeeded.', [TargetSessionId]));
            FCurrentState := sdpIdle;
          end
          else
          begin
            Log(Format('LaunchUserSessionManager(Session: %d) failed.', [TargetSessionId]));
          end;
          FInvokerRequests := TIdHTTPWebBrokerBridge.Create(Self);
          FInvokerRequests.Bindings.Clear;
          FInvokerRequests.DefaultPort := SDServiceRequestPort;
          FInvokerRequests.Active := TRUE;
        end;
      sdpIdle:
        begin
          // Retrieve command from initiating user application via SOAP
          // If there are no commands, then Sleep(100);
          Sleep(100);

          // Simulating user command:
          //FCurrentState := sdpShowApplication;
          //FCurrentApplicationId := 2;
        end;
      sdpShowApplication:
        begin
          // Log(Format(ExtractFilePath(ParamStr(0)) + 'SDAppInfo.exe %d', [ApplicationId]));
          // SDCreateProcess(ExtractFilePath(ParamStr(0)) + 'SDAppInfo.exe', IntToStr(ApplicationId));
          // SDCreateProcess(ExtractFilePath(ParamStr(0)) + 'SDDumpDesktopACL.exe', '');

          SDWriteToMailslot(FUserSessionManagerCommands,
            Format('%s %d', [SDP_REQUEST_LAUNCH_APP, FCurrentApplicationId]));
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 2000);
          Log(Format('Response: %s', [sResponse]));

          // SDCreateProcess('C:\Windows\system32\calc.exe', '');
          // SDCreateProcess('C:\Windows\system32\notepad.exe', '');
          Sleep(1000);
          SDWriteToMailslot(FUserSessionManagerCommands, SDP_REQUEST_SWITCH_TO_SECUREDESKTOP);
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 2000);
          Log(Format('Response: %s', [sResponse]));

          Sleep(8000);
          FCurrentState := sdpHideApplication;
        end;
      sdpHideApplication:
        begin
          SDWriteToMailslot(FUserSessionManagerCommands, SDP_REQUEST_SWITCH_TO_USERDESKTOP);
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 2000);
          Log(Format('Response: %s', [sResponse]));

          SDWriteToMailslot(FUserSessionManagerCommands, SDP_REQUEST_CLEAR_SECUREDESKTOP);
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 5000);
          Log(Format('Response: %s', [sResponse]));

          SDWriteToMailslot(FUserSessionManagerCommands, SDP_REQUEST_GET_LIFESIGN);
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 1000);
          Log(Format('Response: %s', [sResponse]));

          FCurrentState := sdpQuit;
        end;
      sdpQuit:
        begin
          FShouldTerminate := true;
          SDWriteToMailslot(FUserSessionManagerCommands, SDP_REQUEST_QUIT);
          SDReadFromMailslot(FUserSessionManagerResponse, sResponse, 5000);
          Log(Format('Response: %s', [sResponse]));
        end;
    else
      begin
        Log(Format('Unexpected internal state: %d', [Ord(FCurrentState)]));
      end;
    end;
  end;

  Log('Quitting');




  // 1. Add a unique group (to simulate a capability)
  // 2. Add a new desktop in the interactive window station of the target session
  // - ACL of that desktop requires the unique group
  // - Owner of the desktop should be local system, i.e., the account of this service
  // - Use mail slots with local system ACL
  // - Wait for signal from ManageSecureDesktop.exe, then log success

  // 3. Start the target process with a modified token - that has the unique group included - on the new desktop
  // - Include custom shell that displays the application hologram
  // StartInSession('C:\Windows\system32\calc.exe', TargetSessionId,
  // SecureViewerDesktopName);

  // StartInSession(ExtractFilePath(ParamStr(0)) + 'DumpSessionDetails.exe',
  // TargetSessionId, 'Default');

  // 4. Switch input to the new desktop
  // - Signal to shell that desktop should be switched

  // 5. When required, switch input back to original desktop
  // - Signal to shell that desktop should be switched
  // - Maybe need to kill remaining processes on new desktop

  // 6. Remove new desktop
  // - Desktop cannot be removed
  // - Kill all processes and set ACL for desktop so that only local system can access

  // 7. Remove unique group



  // Probably use a separate process in target session to create desktop
  // Make sure that process has an appropriate ACL in SD so that code cannot be injected

  // IMPORTANT
  // JwsclSid.JwInitSidNameCache;
  // SDEnumerateProcessesSilently(Processes);
  // SDProcessAllPIDS(Processes, AddGroupToToken, 0);

  // SDEnumerateProcesses(Processes);
  // SDProcessAllPIDS(Processes, @SDDumpProcessToken, 0);
  // SDProcessAllPIDS(Processes, @SDDumpProcessThreads, 0);

  {

    //Windows.Beep(440, 500);


    // Start calc.exe with bds.exe token
    // Start notepad.exe with bds.exe token, amended by unique group entry

    SDEnumerateProcessesSilently(AllProcesses);
    nProcessIndex := 0;
    while ((nProcessIndex < AllProcesses.ProcessCount) and (AllProcesses.Processes[nProcessIndex].FileName <> 'bds.exe')) do
    begin
    // Log(Format('Session %d  PID %.5d  %s', [AllProcesses.Processes[nProcessIndex].SessionID, AllProcesses.Processes[nProcessIndex].PID, AllProcesses.Processes[nProcessIndex].FileName]));
    nProcessIndex := nProcessIndex + 1;
    end;
    Log(Format('Session %d  PID %.5d  %s', [AllProcesses.Processes[nProcessIndex].SessionID, AllProcesses.Processes[nProcessIndex].PID, AllProcesses.Processes[nProcessIndex].FileName]));
    if OpenProcessToken(
    OpenProcess(PROCESS_QUERY_INFORMATION, false, AllProcesses.Processes[nProcessIndex].PID),
    TOKEN_ALL_ACCESS, hUserDesktopProcessToken) then
    begin
    Log('OpenProcessToken() succeeded.');
    //SDCreateProcess('C:\Windows\system32\calc.exe');
    //SDCreateProcess('C:\Windows\system32\notepad.exe');

    if Windows.DuplicateTokenEx(hUserDesktopProcessToken, Windows.MAXIMUM_ALLOWED, nil,
    Windows.SecurityImpersonation, Windows.TokenPrimary, hUsualUserToken) then
    begin
    Log('DuplicateTokenEx() succeeded.');
    SessionId := WTSGetActiveConsoleSessionId;
    SetTokenInformation(hUsualUserToken, TokenSessionId, @SessionId, SizeOf(SessionId));
    SDCreateProcessWithTokenOnDesktop('C:\Windows\system32\charmap.exe', hUsualUserToken, SecureViewerDesktopName);

    //if DuplicateTokenEx(hUserDesktopProcessToken, Windows.MAXIMUM_ALLOWED, nil,
    //  Windows.SecurityImpersonation, Windows.TokenPrimary, hSecureViewerGroupEnabledToken) then
    if true then
    begin
    //Log('DuplicateTokenEx() succeeded.');

    // Add group to token
    if SDAcquireTCBPrivilege then
    begin
    Log('SDAcquireTCBPrivilege() succeeded.');
    SecurityQualityOfService.Length := SizeOf(SecurityQualityOfService);
    SecurityQualityOfService.ImpersonationLevel := SecurityImpersonation;
    SecurityQualityOfService.ContextTrackingMode := SECURITY_STATIC_TRACKING;
    SecurityQualityOfService.EffectiveOnly := false;
    ObjectAttributes.Length := SizeOf(ObjectAttributes);
    ObjectAttributes.SecurityQualityOfService := @SecurityQualityOfService;

    //AuthenticationId := ProcessToken.GetTokenStatistics.AuthenticationId;
    //ExpirationTime := ProcessToken.GetTokenStatistics.ExpirationTime;
    GetTokenInformation(hUserDesktopProcessToken, TokenStatistics, nil, 0, dwReturnLength);
    GetMem(UserDesktopProcessTokenStatistics, dwReturnLength);
    if GetTokenInformation(hUserDesktopProcessToken, TokenStatistics, UserDesktopProcessTokenStatistics, dwReturnLength, dwReturnLength) then
    begin
    AuthenticationId := UserDesktopProcessTokenStatistics^.AuthenticationId;
    ExpirationTime := UserDesktopProcessTokenStatistics^.ExpirationTime;
    end
    else
    begin
    Log(Format('GetTokenInformation(TokenStatistics) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    //FillChar(User.User, SizeOf(User.User), 0);
    //User.User.Sid := ProcessToken.GetTokenUser.CreateCopyOfSID;
    GetTokenInformation(hUserDesktopProcessToken, TokenUser, nil, 0, dwReturnLength);
    GetMem(User, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenUser, User, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenUser) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    GetTokenInformation(hUserDesktopProcessToken, TokenGroups, nil, 0, dwReturnLength);
    Log('TokenGroups');
    Log(Format('dwReturnLength: %d  SizeOf(Windows.SID_AND_ATTRIBUTES): %d', [dwReturnLength, SizeOf(Windows.SID_AND_ATTRIBUTES)]));
    //GetMem(Groups, dwReturnLength + SizeOf(Windows.SID_AND_ATTRIBUTES));
    GetMem(Groups, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenGroups, Groups, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenGroups) failed: %s', [SysErrorMessage(GetLastError)]));
    end;
    Log(Format('Groups^.GroupCount: %d', [Groups^.GroupCount]));

    ////Groups := SDAddGroupToToken(ProcessToken.GetTokenGroups.Create_PTOKEN_GROUPS,
    ////  GroupSid);

    //Privileges := ProcessToken.GetTokenPrivileges.Create_PTOKEN_PRIVILEGES;
    GetTokenInformation(hUserDesktopProcessToken, TokenPrivileges, nil, 0, dwReturnLength);
    GetMem(Privileges, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenPrivileges, Privileges, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenPrivileges) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    //Owner.Owner := ProcessToken.GetTokenOwner.CreateCopyOfSID;
    GetTokenInformation(hUserDesktopProcessToken, TokenOwner, nil, 0, dwReturnLength);
    GetMem(Owner, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenOwner, Owner, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenOwner) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    //PrimaryGroup.PrimaryGroup := ProcessToken.GetPrimaryGroup.CreateCopyOfSID;
    GetTokenInformation(hUserDesktopProcessToken, TokenPrimaryGroup, nil, 0, dwReturnLength);
    GetMem(PrimaryGroup, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenPrimaryGroup, PrimaryGroup, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenPrimaryGroup) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    //DefaultDacl.DefaultDacl := ProcessToken.GetTokenDefaultDacl.Create_PACL;
    GetTokenInformation(hUserDesktopProcessToken, TokenDefaultDacl, nil, 0, dwReturnLength);
    GetMem(DefaultDacl, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenDefaultDacl, DefaultDacl, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenDefaultDacl) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    //Source.SourceName := 'SecDesk';
    //Source.SourceIdentifier.LowPart := 0;
    //Source.SourceIdentifier.HighPart := 0;
    GetTokenInformation(hUserDesktopProcessToken, TokenSource, nil, 0, dwReturnLength);
    GetMem(Source, dwReturnLength);
    if (not GetTokenInformation(hUserDesktopProcessToken, TokenSource, Source, dwReturnLength, dwReturnLength)) then
    begin
    Log(Format('GetTokenInformation(TokenSource) failed: %s', [SysErrorMessage(GetLastError)]));
    end;

    hSecureViewerGroupEnabledToken := 0;
    cStatus := ZwCreateToken(@hSecureViewerGroupEnabledToken,
    TOKEN_ALL_ACCESS, @ObjectAttributes,
    Windows.TokenPrimary, @AuthenticationId, @ExpirationTime, User,
    Groups,
    Privileges, Owner, PrimaryGroup, DefaultDacl, Source
    );
    Log(Format('ZwCreateToken(): %d  LastError: %s', [cStatus, SysErrorMessage(cStatus)]));

    Log(Format('Session (hSecureViewerGroupEnabledToken): %d', [GetTokenSessionId(hSecureViewerGroupEnabledToken)]));
    Log(Format('Session (hUserDesktopProcessToken): %d', [GetTokenSessionId(hUserDesktopProcessToken)]));
    SessionId := GetTokenSessionId(hUserDesktopProcessToken);
    //SDDumpThreadPrivileges(GetCurrentThread);
    if SetTokenInformation(hSecureViewerGroupEnabledToken, TokenSessionId, @SessionID, SizeOf(SessionID)) then
    begin
    Log('SetTokenInformation() succeeded.');
    end
    else
    begin
    Log(Format('SetTokenInformation() failed: %s', [SysErrorMessage(GetLastError)]));
    end;
    Log(Format('Session (hSecureViewerGroupEnabledToken): %d', [GetTokenSessionId(hSecureViewerGroupEnabledToken)]));
    GetTokenUser(hSecureViewerGroupEnabledToken);
    GetTokenGroups(hSecureViewerGroupEnabledToken);

    SDCreateProcessWithTokenOnDesktop('C:\Windows\system32\notepad.exe', hSecureViewerGroupEnabledToken, SecureViewerDesktopName);
    //SDCreateProcessWithTokenOnDesktop('C:\Windows\system32\calc.exe', hUserDesktopProcessToken, SecureViewerDesktopName);
    SDReleaseTCBPrivilege;
    end
    else
    begin
    Log('SDAcquireTCBPrivilege() failed.');
    end;
    end
    else
    begin
    Log(Format('DuplicateTokenEx() failed: %s', [SysErrorMessage(GetLastError)]));
    end;
    end
    else
    begin
    Log(Format('DuplicateTokenEx() failed: %s', [SysErrorMessage(GetLastError)]));
    end;
    end;

    // 1. Use desktop with Everyone SID: both windows should appear
    // 2. Use desktop with unique group SID: only notepad.exe should appear

  }

  Log('Service completed');
end;

end.
