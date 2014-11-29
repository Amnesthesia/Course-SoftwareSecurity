program SDUserSessionManager;

{$APPTYPE CONSOLE}

{$R 'SDUserSessionManager.res' 'SDUserSessionManager.rc'}

uses
  SysUtils,
  Windows,
  AccCtrl,
  AclApi,
  SDCommon in 'SDCommon.pas',
  SDInfoProcesses in 'SDInfoProcesses.pas',
  SDModifiedTokens in 'SDModifiedTokens.pas',
  SDProtocol in 'SDProtocol.pas';

type
  PUNICODE_STRING = ^UNICODE_STRING;
{$EXTERNALSYM PUNICODE_STRING}

  _UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    // Buffer: PWSTR;
    Buffer: Pointer;
  end;
{$EXTERNALSYM _UNICODE_STRING}

  UNICODE_STRING = _UNICODE_STRING;
{$EXTERNALSYM UNICODE_STRING}
  PCUNICODE_STRING = ^UNICODE_STRING;
{$EXTERNALSYM PCUNICODE_STRING}
  TUnicodeString = UNICODE_STRING;
  PUnicodeString = PUNICODE_STRING;

  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;
{$EXTERNALSYM POBJECT_ATTRIBUTES}

  _OBJECT_ATTRIBUTES = record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: ULONG;
    SecurityDescriptor: PVOID; // Points to type SECURITY_DESCRIPTOR
    SecurityQualityOfService: PVOID; // Points to type SECURITY_QUALITY_OF_SERVICE
  end;
{$EXTERNALSYM _OBJECT_ATTRIBUTES}

  OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
{$EXTERNALSYM OBJECT_ATTRIBUTES}
  TObjectAttributes = OBJECT_ATTRIBUTES;
  PObjectAttributes = POBJECT_ATTRIBUTES;

function ZwCreateToken(TokenHandle: PHANDLE; DesiredAccess: ACCESS_MASK;
  ObjectAttributes: POBJECT_ATTRIBUTES; // POBJECT_ATTRIBUTES;
  ATokenType: Windows.TTokenType; // TOKEN_TYPE;
  AuthenticationId: PLUID; ExpirationTime: Windows.PLargeInteger; // PLARGE_INTEGER;
  User: Windows.PTokenUser; Groups: Windows.PTokenGroups; Privileges: Windows.PTokenPrivileges;
  Owner: Windows.PTokenOwner; PrimaryGroup: Windows.PTokenPrimaryGroup;
  DefaultDacl: Windows.PTokenDefaultDacl; Source: Windows.PTokenSource): Cardinal; stdcall;
  external 'ntdll' name 'NtCreateToken';

var
  CurrentState: TSDPState;
  hCommandMailslot: THandle;
  sMessage: string;
  hResponseMailslot: THandle;
  sCommand: string;
  hUserDesktop: THandle;
  hSecureDesktop: THandle;
  cApplicationId: Cardinal;

  AllProcesses: TProcesses;
  // cProcessIndex: Cardinal;
  // hUserDesktopProcessToken: THandle;
  // hUsualUserToken: THandle;
  // hSecureViewerGroupEnabledToken: THandle;

  // dwReturnLength: DWORD;
  // SecurityQualityOfService: TSecurityQualityOfService;
  // ObjectAttributes: TObjectAttributes;
  // UserDesktopProcessTokenStatistics: Windows.PTokenStatistics;
  // AuthenticationId: TLUID;
  // ExpirationTime: LARGE_INTEGER;
  // User:  Windows.PTokenUser;
  // Groups: Windows.PTokenGroups;
  // Privileges: PTokenPrivileges;
  // Owner: Windows.PTokenOwner;
  // PrimaryGroup: Windows.PTokenPrimaryGroup;
  // DefaultDacl: Windows.PTokenDefaultDacl;
  // Source: Windows.PTokenSource;
  // SessionID: DWORD;
  // cStatus: Cardinal;

  MyProcessData: TProcessData;
  // BackgroundBitmap: Graphics.TBitmap;

  SI: Windows.TStartupInfo;
  NewProcessInformation: Windows.TProcessInformation;

begin
  try
    CurrentState := sdpCreated;
    hUserDesktop := 0;
    hSecureDesktop := 0;
    while (CurrentState <> sdpQuit) do
    begin
      case CurrentState of
        sdpCreated:
          begin
            Log('Entered sdpCreated state');
            CurrentState := sdpQuit;
            if SDCreateSecureMailslot(SecureViewerMailslotForUserSessionManager,
              hCommandMailslot) then
            begin
              Log('SDCreateSecureMailslot() succeeded.');
              if SDOpenMailslot(SecureViewerMailslotForBackgroundService, hResponseMailslot) then
              begin
                Log('SDOpenMailslot() succeeded.');
                if SDAddSecureViewerProcessGroup then
                begin
                  Log('AddSecureViewerProcessGroup() succeeded.');
                  hUserDesktop := OpenInputDesktop(0, false, DESKTOP_SWITCHDESKTOP);
                  hSecureDesktop := SDCreateSecureDesktop(SecureViewerDesktopName);
                  if ((hUserDesktop <> 0) and (hUserDesktop <> INVALID_HANDLE_VALUE) and
                    (hSecureDesktop <> 0) and (hSecureDesktop <> INVALID_HANDLE_VALUE)) then
                  begin
                    Log('OpenInputDesktop() and SDCreateSecureUserDesktop() succeeded.');
                    SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_READY +
                      SDP_READY_MESSAGE);
                    CurrentState := sdpIdle;
                  end;
                end;
              end
              else
              begin
                Log(Format('SDOpenMailslot() failed: %s', [SysErrorMessage(GetLastError)]));
              end;
            end
            else
            begin
              Log(Format('SDCreateSecureMailslot() failed: %s', [SysErrorMessage(GetLastError)]));
            end;
          end;
        sdpIdle:
          begin
            while SDIsMailslotEmpty(hCommandMailslot) do
            begin
              Sleep(100);
            end;
            SDReadFromMailslot(hCommandMailslot, sMessage);
            Log(Format('Message from background service: "%s"', [sMessage]));
            if SDMessageMatches(sMessage, SDP_REQUEST_SWITCH_TO_SECUREDESKTOP) then
            begin
              // Take a screenshot of the primary monitor or of all monitors
              // Dim the screenshot, save it to file to be picked up by SDAppInfo
              // BackgroundBitmap := Screenshot.GetDimmed;
              if SwitchDesktop(hSecureDesktop) then
              begin
                Log('SwitchDesktop() succeeded.');
                SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_SWITCHED_TO_SECUREDESKTOP +
                  SDP_SWITCHED_TO_SECUREDESKTOP_MESSAGE);
              end
              else
              begin
                Log('SwitchDesktop() failed.');
                SDWriteToMailslot(hResponseMailslot, SDP_ERROR + SDP_SWITCHED_TO_SECUREDESKTOP);
              end;
            end
            else if SDMessageMatches(sMessage, SDP_REQUEST_SWITCH_TO_USERDESKTOP) then
            begin
              if SwitchDesktop(hUserDesktop) then
              begin
                Log('SwitchDesktop() succeeded.');
                SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_SWITCHED_TO_USERDESKTOP +
                  SDP_SWITCHED_TO_USERDESKTOP_MESSAGE);
              end
              else
              begin
                Log('SwitchDesktop() failed.');
                SDWriteToMailslot(hResponseMailslot, SDP_ERROR + SDP_SWITCHED_TO_USERDESKTOP);
              end;
            end
            else if SDMessageMatches(sMessage, SDP_REQUEST_LAUNCH_APP) then
            begin
              cApplicationId :=
                StrToIntDef(Copy(sMessage, Length(SDP_REQUEST_LAUNCH_APP) + 1 + 1, 5), 0);
              // Check whether application configuration data is retrievable
              if (cApplicationId <> 0) then
              begin
                Log('Valid application id with retrievable configuration data found.');
                // Launch secure desktop shell (without privileges)

                Log(Format(ExtractFilePath(ParamStr(0)) + 'SDAppInfo.exe %d', [cApplicationId]));

                ZeroMemory(@SI, SizeOf(SI));
                Windows.CreateProcess(PChar(ExtractFilePath(ParamStr(0)) + 'SDDumpDesktopACL.exe'),
                  PChar(''), nil, nil, false, 0, nil, nil, SI, NewProcessInformation);

                SDCreateProcess(ExtractFilePath(ParamStr(0)) + 'SDAppInfo.exe', IntToStr(cApplicationId));
                SDCreateProcess(SDAppInfoApplicationExecutable(cApplicationId),
                  SDAppInfoApplicationCommandLine(cApplicationId));
                // SDCreateProcess(ExtractFilePath(ParamStr(0)) + 'SDDumpDesktopACL.exe', '');
                // SDCreateProcess('C:\Windows\system32\calc.exe', '');
                // SDCreateProcess('C:\Windows\system32\notepad.exe', '');

                // Retrieve configuration data
                // Put configuration data in temporary file protected by secure group ACL
                SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_LAUNCHED_APP +
                  SDP_LAUNCHED_APP_MESSAGE + ' ' + IntToStr(cApplicationId));
              end
              else
              begin
                Log('Invalid application id or configuration data could not be found.');
                SDWriteToMailslot(hResponseMailslot, SDP_ERROR + SDP_LAUNCHED_APP + ' ' +
                  IntToStr(cApplicationId));
              end;
            end
            else if SDMessageMatches(sMessage, SDP_REQUEST_CLEAR_SECUREDESKTOP) then
            begin
              if SDClearSecureDesktop(SecureViewerDesktopName) then
              begin
                Log('SDClearSecureDesktop() succeeded.');
                // Remove temporary file with configuration data
                // Remove group
                SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_CLEARED_SECUREDESKTOP +
                  SDP_CLEARED_SECUREDESKTOP_MESSAGE);
              end
              else
              begin
                Log('SDClearSecureDesktop() failed.');
                SDWriteToMailslot(hResponseMailslot, SDP_ERROR + SDP_CLEARED_SECUREDESKTOP);
              end;
            end
            else if SDMessageMatches(sMessage, SDP_REQUEST_GET_LIFESIGN) then
            begin
              SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_LIFESIGN +
                SDP_LIFESIGN_MESSAGE);
            end
            else if SDMessageMatches(sMessage, SDP_REQUEST_QUIT) then
            begin
              CurrentState := sdpQuit;
              SDWriteToMailslot(hResponseMailslot, SDP_SUCCESS + SDP_QUIT + SDP_QUIT_MESSAGE);
            end
            else
            begin
              Log(Format('Unexpected request: "%s"', [sMessage]));
            end

          end;
        sdpQuit:
          begin
            Log('Entered sdpQuit state');
            // Prepare restart, then exit while loop
          end;
      else
        begin
          Log(Format('Unexpected internal state: %d', [Ord(CurrentState)]));
        end;
      end;
    end;

    Log('Quitting');
    if SwitchDesktop(hUserDesktop) then
    begin
      Log('SwitchDesktop() succeeded.');
    end
    else
    begin
      Log('SwitchDesktop() failed.');
      SDWriteToMailslot(hResponseMailslot, SDP_ERROR + SDP_SWITCHED_TO_USERDESKTOP);
    end;
    if SDRemoveSecureViewerProcessGroup then
    begin
      Log('RemoveSecureViewerProcessGroup() succeeded.');
    end;
    // Log('Retrieving session details');
    // if SDRetrieveWindowStationsAndDesktops then
    // begin
    // Log('Retrieved window stations and desktops');
    // Log('Dumping window station and desktop ACLs');
    // SDDumpWindowStationAndDesktopSecurityInformation;
    // end;
    Log('Final log entry.');
    Log('');
    Log('');
  except
    on E: Exception do
    begin
      Log(E.ClassName + ': ' + E.Message);
    end;
  end;

end.
