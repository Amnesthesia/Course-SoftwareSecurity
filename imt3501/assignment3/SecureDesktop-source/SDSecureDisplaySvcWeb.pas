unit SDSecureDisplaySvcWeb;

interface

uses
  SysUtils, Classes, HTTPApp, InvokeRegistry, WSDLIntf, TypInfo, WebServExp, WSDLBind, XMLSchema,
  WSDLPub, SOAPPasInv, SOAPHTTPPasInv, SOAPHTTPDisp, WebBrokerSOAP;

type
  TSecureDisplaySvcWeb = class(TWebModule)
    HTTPSoapDispatcher: THTTPSoapDispatcher;
    HTTPSoapPascalInvoker: THTTPSoapPascalInvoker;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  WebModuleClass: TComponentClass = TSecureDisplaySvcWeb;

implementation

{$R *.dfm}

end.
