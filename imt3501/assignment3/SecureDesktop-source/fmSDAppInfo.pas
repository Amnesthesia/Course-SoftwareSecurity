unit fmSDAppInfo;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ExtCtrls, ShellApi, StdCtrls;

type
  TfmAppInfo = class(TForm)
    CloseTimer: TTimer;
    RefreshTimer: TTimer;
    panelBackground: TPanel;
    imgBackground: TImage;
    panelAppInfo: TPanel;
    imgApplicationLogo: TImage;
    lblApplicationName: TLabel;
    procedure FormCreate(Sender: TObject);
    procedure CloseTimerTimer(Sender: TObject);
    procedure RefreshTimerTimer(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
    ApplicationKey: Integer;
    FAppInfoBarData: TAppBarData;
    FOldWorkArea: TRect;
    function DisplayAppInfo(const AKey: Integer): Boolean;
    function CreateAppBar: Boolean;
    function RemoveAppBar: Boolean;
    function RestrictWorkArea: Boolean;
    procedure RestoreWorkArea;
    function StartApp(const AKey: Integer): Boolean;
    procedure PaintBackground;
  public
    { Public declarations }
  end;

var
  fmAppInfo: TfmAppInfo;

implementation

uses
  PNGImage, SDCommon, dmScreenshot;

{$R *.dfm}

const
  WM_SD_APPINFOBAR = WM_USER + 42;



function TfmAppInfo.CreateAppBar: Boolean;
begin
  Result := false;
  ZeroMemory(@FAppInfoBarData, SizeOf(TAppBarData));
  FAppInfoBarData.cbSize := SizeOf(TAppBarData);
  FAppInfoBarData.hWnd := Handle;
  FAppInfoBarData.uCallbackMessage := WM_SD_APPINFOBAR;
  if (SHAppBarMessage(ABM_NEW, FAppInfoBarData) <> 0) then
  begin
    Log('SHAppBarMessage(ABM_NEW) succeeded.');
    FAppInfoBarData.uEdge := ABE_TOP;
    FAppInfoBarData.rc := Rect(0, 0, Width, Height);
    if (SHAppBarMessage(ABM_QUERYPOS, FAppInfoBarData) <> 0) then
    begin
      Log('SHAppBarMessage(QUERYPOS) succeeded.');
      Log(Format('QUERYPOS: Left: %d   Top: %d  Right: %d  Bottom: %d', [FAppInfoBarData.rc.Left,
        FAppInfoBarData.rc.Top, FAppInfoBarData.rc.Right, FAppInfoBarData.rc.Bottom]));
      if (SHAppBarMessage(ABM_SETPOS, FAppInfoBarData) <> 0) then
      begin
        Log('SHAppBarMessage(ABM_SETPOS) succeeded.');
        Application.ProcessMessages;
        Result := (SHAppBarMessage(ABM_ACTIVATE, FAppInfoBarData) <> 0);
        Top := 0;
      end
      else
      begin
        Log(Format('SHAppBarMessage(ABM_SETPOS) failed: %s', [SysErrorMessage(GetLastError)]));
      end;
    end
    else
    begin
      Log(Format('SHAppBarMessage(ABM_QUERYPOS) failed: %s', [SysErrorMessage(GetLastError)]));
    end;
  end
  else
  begin
    Log(Format('SHAppBarMessage(ABM_NEW) failed: %s', [SysErrorMessage(GetLastError)]));
  end;
end;

function TfmAppInfo.DisplayAppInfo(const AKey: Integer): Boolean;
begin
  imgApplicationLogo.Picture.LoadFromFile(SDAppInfoFullLogoFileName(AKey));
  //Log(Format('+imgApplicationLogo.Picture.LoadFromFile(%s)',
  //  [SDAppInfoFullLogoFileName(AKey)]));

  panelAppInfo.Caption := '';
  panelAppInfo.Top := Screen.WorkAreaTop - panelAppInfo.Parent.Top;
  panelAppInfo.Left := Screen.WorkAreaLeft - panelAppInfo.Parent.Left;
  panelAppInfo.Width := Screen.Width;
  panelAppInfo.Height := imgApplicationLogo.Height;
  panelAppInfo.Color := RGB($1B, $58, $B8);
  imgApplicationLogo.Top := 0;
  imgApplicationLogo.Left := panelAppInfo.Width - imgApplicationLogo.Width;

  lblApplicationName.Font.Color := clWhite;
  lblApplicationName.Font.Height := 40;
  lblApplicationName.Font.Name := 'Segoe UI Light';
  //lblApplicationName.Caption := SDAppInfoApplicationExecutable(AKey);
  lblApplicationName.Caption := SDAppInfoApplicationName(AKey);
  lblApplicationName.Top := (panelAppInfo.Height - lblApplicationName.Height) div 2;
  lblApplicationName.Left := (panelAppInfo.Width - imgApplicationLogo.Width - lblApplicationName.Width) div 2;

  Result := true;
end;

procedure TfmAppInfo.FormCreate(Sender: TObject);
begin
  if ParamCount = 1 then
  begin
    ApplicationKey := StrToIntDef(ParamStr(1), -1);
  end
  else
  begin
    ApplicationKey := -1;
  end;

  // +add check of PE signature

  // Draw the dimmed screenshot on the whole desktop
  PaintBackground;
  DisplayAppInfo(ApplicationKey);
  //CreateAppBar;
  RestrictWorkArea;

  StartApp(ApplicationKey);

  Windows.Beep(880, 200);
  RefreshTimer.Enabled := true;

  Log('End of FormCreate()');
end;

procedure TfmAppInfo.FormDestroy(Sender: TObject);
begin
  RemoveAppBar;
  RestoreWorkArea;
end;

procedure TfmAppInfo.PaintBackground;
begin
  panelBackground.Caption := '';
  imgBackground.Picture.LoadFromFile(SDAppInfoBackgroundBitmapFileName);
  imgBackground.Left := 0;
  imgBackground.Top := 0;
  Windows.SetParent(panelBackground.Handle, 0);
  panelBackground.Left := Screen.DesktopLeft;
  panelBackground.Top := Screen.DesktopTop;
  panelBackground.Width := imgBackground.Width;
  panelBackground.Height := imgBackground.Height;
end;

procedure TfmAppInfo.RefreshTimerTimer(Sender: TObject);
begin
  Hide;
  //lblApplicationName.Caption := Format('Top: %d', [Top]);
end;

function TfmAppInfo.RemoveAppBar: Boolean;
begin
  ZeroMemory(@FAppInfoBarData, SizeOf(TAppBarData));
  FAppInfoBarData.cbSize := SizeOf(TAppBarData);
  FAppInfoBarData.hWnd := Handle;
  Result := (SHAppBarMessage(ABM_REMOVE, FAppInfoBarData) <> 0);
end;

procedure TfmAppInfo.RestoreWorkArea;
begin
  SystemParametersInfo(SPI_SETWORKAREA, 0, @FOldWorkArea, SPIF_SENDCHANGE);
end;

function TfmAppInfo.RestrictWorkArea: Boolean;
var
  RestrictedWorkArea: TRect;
begin
  // Works only on primary monitor; for a different monitor call GetMonitorInfo()
  SystemParametersInfo(SPI_GETWORKAREA, 0, @FOldWorkArea, 0);
  RestrictedWorkArea := FOldWorkArea;
  RestrictedWorkArea.Top := RestrictedWorkArea.Top + panelAppInfo.Height;
  SystemParametersInfo(SPI_SETWORKAREA, 0, @RestrictedWorkArea, 0);
  Result := TRUE;
end;

function TfmAppInfo.StartApp(const AKey: Integer): Boolean;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
begin
  FillChar(SI, SizeOf(TStartupInfo), 0);
  FillChar(PI, SizeOf(TProcessInformation), 0);
  SI.cb := SizeOf(TStartupInfo);
  SI.dwFlags := STARTF_USESHOWWINDOW;
  SI.wShowWindow := SW_SHOWMAXIMIZED;
  SI.dwX := Screen.WorkAreaLeft;
  SI.dwY := Screen.WorkAreaTop;
  SI.dwXSize := Screen.WorkAreaWidth;
  SI.dwYSize := Screen.WorkAreaHeight;

  Result := CreateProcess(PChar(SDAppInfoApplicationExecutable(AKey)), nil, nil, nil, false, 0,
    nil, nil, SI, PI);
  Log('CreateProcess()');
end;

procedure TfmAppInfo.CloseTimerTimer(Sender: TObject);
begin
  Close;
end;

end.
