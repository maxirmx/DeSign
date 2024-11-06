program DeSign;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  JwaWinCrypt;

type
  TCertOption = record
    FriendlyName: string;
    Thumbprint: array of Byte;
  end;

  TCertOptions = record
    Certs: array of TCertOption;
    Error: string;
  end;

procedure PrintHexWithColons(const Data: array of Byte);
var
  I: Integer;
begin
  for I := Low(Data) to High(Data) do
  begin
    if I > Low(Data) then
      Write(':');
    Write(Format('%02x', [Data[I]]));
  end;
  Writeln;
end;

procedure EmplaceError(var Res: TCertOptions; const Msg: string);
var
  ErrorCode: DWORD;
  Buffer: PChar;
begin
  ErrorCode := GetLastError();
  FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
    nil,
    ErrorCode,
    LANG_NEUTRAL,
    @Buffer,
    0,
    nil
  );
  Res.Error := Msg + ' [' + IntToStr(ErrorCode) + '] ' + string(Buffer);
  LocalFree(HLOCAL(Buffer));
end;

function GetCertificates(const Prefix: string): TCertOptions;
var
  Res: TCertOptions;
  hStoreHandle: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  AlgorithmID: string;
  FriendlyName: array[0..255] of Char;
  Thumbprint: array[0..19] of Byte;
  ThumbprintSize: DWORD;
  CertOption: TCertOption;
begin
  hStoreHandle := CertOpenSystemStore(0, 'MY');
  if hStoreHandle = nil then
  begin
    EmplaceError(Res, '?? ??????? ??????? ????????? ????????????.');
    GetCertificates := Res;
    Exit
  end;

  pCertContext := nil;
  while True do
  begin
    pCertContext := CertEnumCertificatesInStore(hStoreHandle, pCertContext);
    if pCertContext = nil then
      Break;

    AlgorithmID := pCertContext^.pCertInfo^.SignatureAlgorithm.pszObjId;
    if Pos(Prefix, AlgorithmID) <> 1 then
      Continue;

    if (CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nil, FriendlyName, SizeOf(FriendlyName)) = 1) or
       (FriendlyName[0] = #0) then
    begin
      if CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, FriendlyName, SizeOf(FriendlyName)) = 1 then
      begin
        EmplaceError(Res, '?? ??????? ???????? "Subject" ??? ???????????.');
        GetCertificates := Res;
        Exit
      end;
    end;

    ThumbprintSize := SizeOf(Thumbprint);
    if not CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, @Thumbprint, ThumbprintSize) then
    begin
      EmplaceError(Res, '?? ??????? ???????? "Thumbprint" ??? ???????????.');
      GetCertificates := Res;
      Exit
    end;

    SetLength(CertOption.Thumbprint, ThumbprintSize);
    Move(Thumbprint, CertOption.Thumbprint[0], ThumbprintSize);
    CertOption.FriendlyName := FriendlyName;
    SetLength(Res.Certs, Length(Res.Certs) + 1);
    Res.Certs[High(Res.Certs)] := CertOption;
  end;

  if not CertCloseStore(hStoreHandle, 0) then
    EmplaceError(Res, '?? ??????? ??????? ????????? ????????????.');

  GetCertificates := Res;
end;

var
  Res: TCertOptions;
  I: Integer;
begin
  try
    Writeln('Hello World!');

    Res := GetCertificates('1.2.643');

    if Res.Error <> '' then
    begin
      Writeln(Res.Error);
      Exit;
    end;

    for I := Low(Res.Certs) to High(Res.Certs) do
    begin
      Writeln('Friendly Name: ', Res.Certs[I].FriendlyName);
      Write('Thumbprint: ');
      PrintHexWithColons(Res.Certs[I].Thumbprint);
    end;
  except
    on E: Exception do
      Write ln(E.ClassName, ': ', E.Message);
  end;
end.

