unit dmScreenshot;

interface

uses
  SysUtils, Classes, ASGCapture, Graphics;

type
  TScreenshot = class(TDataModule)
    ScreenCapture: TASGScreenCapture;
  private
    { Private declarations }
  public
    { Public declarations }
    function GetBitmap: Graphics.TBitmap;
    function GetDimmed: Graphics.TBitmap;
    function DrawScreenbackground(const ABackground: Graphics.TBitmap): Boolean;
  end;

var
  Screenshot: TScreenshot;

implementation

{$R *.dfm}

uses
  Types, Windows, Forms, SDCommon;

function TScreenshot.GetBitmap: Graphics.TBitmap;
begin
  Log('    Entered TScreenshot.Get()');
  Result := Graphics.TBitmap.Create;
  Log('    Result := Graphics.TBitmap.Create;');
  Application := TApplication.Create(nil);
  Application.Initialize;
  Application.Run;
  Result.Assign(ScreenCapture.CaptureWholeDesktop);
  Application.Free;
  Log('    Result.Assign(ScreenCapture.CaptureWholeDesktop);');
end;

function TScreenshot.GetDimmed: Graphics.TBitmap;
var
  BlendBitmap: Graphics.TBitmap;
begin
  Result := Self.GetBitmap;
  BlendBitmap := Graphics.TBitmap.Create;
  BlendBitmap.Canvas.Brush.Color := clMoneyGreen;
  BlendBitmap.Width := Result.Width;
  BlendBitmap.Height := Result.Height;
  BlendBitmap.Canvas.FillRect(Rect(0, 0, BlendBitmap.Width, BlendBitmap.Height));
  Result.Canvas.Draw(0, 0, BlendBitmap, 127);
  BlendBitmap.Free;
end;

function TScreenshot.DrawScreenbackground(const ABackground: Graphics.TBitmap): Boolean;
begin
  // Log(Format('Screen.DesktopLeft: %d, Screen.DesktopTop: %d', [Screen.DesktopLeft, Screen.DesktopTop]));
  Result := BitBlt(GetDC(GetDesktopWindow), Screen.DesktopLeft, Screen.DesktopTop,
    ABackground.Width, ABackground.Height, ABackground.Canvas.Handle, 0, 0, SRCCOPY);
end;

end.
