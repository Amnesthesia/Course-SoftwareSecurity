program SDAppInfo;

uses
  Forms,
  fmSDAppInfo in 'fmSDAppInfo.pas' {fmAppInfo} ,
  SDCommon in 'SDCommon.pas',
  dmScreenshot in 'dmScreenshot.pas' {Screenshot: TDataModule};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfmAppInfo, fmAppInfo);
  Application.CreateForm(TScreenshot, Screenshot);
  Application.Run;

end.
