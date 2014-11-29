program SDSecureDisplaySvc;

uses
  SvcMgr,
  WebReq,
  IdHTTPWebBrokerBridge,
  SDSecureDisplaySvcUnit in 'SDSecureDisplaySvcUnit.pas' {SDSecureDisplayService: TService},
  SDInfoProcesses in 'SDInfoProcesses.pas',
  SDModifiedTokens in 'SDModifiedTokens.pas',
  SDCommon in 'SDCommon.pas',
  SDProtocol in 'SDProtocol.pas',
  SDInfoSecurity in 'SDInfoSecurity.pas',
  SDSecureDisplaySvcImpl in 'SDSecureDisplaySvcImpl.pas',
  SDSecureDisplaySvcIntf in 'SDSecureDisplaySvcIntf.pas',
  SDSecureDisplaySvcWeb in 'SDSecureDisplaySvcWeb.pas' {SecureDisplaySvcWeb: TWebModule};

{$R *.RES}

begin
  if (WebRequestHandler <> nil) then
    WebRequestHandler.WebModuleClass := WebModuleClass;
  Application.Initialize;
  Application.CreateForm(TSDSecureDisplayService, SDSecureDisplayService);
  Application.Run;

end.
