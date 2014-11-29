{ Invokable interface ISecureDisplaySvc }

unit SDSecureDisplaySvcIntf;

interface

uses InvokeRegistry, Types, XSBuiltIns;

type
  { Invokable interfaces must derive from IInvokable }
  ISecureDisplaySvc = interface(IInvokable)
  ['{6DE725BB-ED95-4F3B-A9EA-9DD8EAB01DBD}']

    { Methods of Invokable interface must not use the default }
    { calling convention; stdcall is recommended }
    function launchApplication(const cApplicationId: Cardinal): Cardinal; stdcall;
    function returnFromApplication(const cApplicationHandle: Cardinal): Cardinal; stdcall;
  end;

implementation

initialization
  { Invokable interfaces must be registered }
  InvRegistry.RegisterInterface(TypeInfo(ISecureDisplaySvc));

end.
