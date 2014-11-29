{ Invokable implementation File for TSecureDisplaySvc which implements ISecureDisplaySvc }

unit SDSecureDisplaySvcImpl;

interface

uses InvokeRegistry, Types, XSBuiltIns, SDSecureDisplaySvcIntf;

type

  { TSecureDisplaySvc }
  TSecureDisplaySvc = class(TInvokableClass, ISecureDisplaySvc)
  public
    function launchApplication(const cApplicationId: Cardinal): Cardinal; stdcall;
    function returnFromApplication(const cApplicationHandle: Cardinal): Cardinal; stdcall;
  end;

implementation

uses
  Windows,
  SysUtils,
  SDCommon,
  SDProtocol,
  SDSecureDisplaySvcUnit;

function TSecureDisplaySvc.launchApplication(const cApplicationId: Cardinal): Cardinal; stdcall;
begin
  Log(Format('SOAP: launchApplication(%d)', [cApplicationId]));
  if (SDSecureDisplayService.CurrentState = sdpIdle) then
  begin
    SDSecureDisplayService.CurrentApplicationId := cApplicationId;
    SDSecureDisplayService.CurrentState := sdpShowApplication;
    Result := SDP_SOAP_RESPONSE_LAUNCHED_APP;
  end
  else
  begin
    Result := SDP_SOAP_RESPONSE_LAUNCH_APP_FAILED;
  end;
end;

function TSecureDisplaySvc.returnFromApplication(const cApplicationHandle: Cardinal): Cardinal; stdcall;
begin
  Log(Format('SOAP: returnFromApplication(%d)', [cApplicationHandle]));
  if (SDSecureDisplayService.CurrentState = sdpIdle) then
  begin
    SDSecureDisplayService.CurrentState := sdpHideApplication;
    Result := SDP_SOAP_RESPONSE_RETURNED_FROM_APP;
  end
  else
  begin
    Result := SDP_SOAP_RESPONSE_RETURN_FROM_APP_FAILED;
  end;
end;


initialization
{ Invokable classes must be registered }
   InvRegistry.RegisterInvokableClass(TSecureDisplaySvc);
end.

