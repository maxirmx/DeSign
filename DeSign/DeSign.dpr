program DeSign;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  JwaWinCrypt,
  CertOptionsList in 'CertOptionsList.pas';

procedure PrintHexWithColons(const Data: TByteArray);
var
  I: Integer;
begin
  for I := Low(Data) to High(Data) do
  begin
    if I > Low(Data) then
      Write(':');
    Write(IntToHex(Data[I], 2));
  end;
  Writeln;
end;

procedure DisplayCertificates;
var
  CertOptions: TCertOptionsList;
  I: Integer;
  CertOption: TCertOption;
begin
  Writeln('���᮪ ���䨪�⮢, ����� �����ন���� ��஢���� �� �����⬠� ����');
  try
    CertOptions := GetCertificates('1.2.643');
    try
      for I := 0 to CertOptions.GetCertCount - 1 do
      begin
        CertOption := CertOptions.GetCertOption(I);
        Writeln('��� ��������: ', CertOption.FriendlyName);
        Write('�������� �⯥�⮪: ');
        PrintHexWithColons(CertOption.Thumbprint);
        Writeln;
      end;
    finally
      CertOptions.Free;
    end;
  except
    on E: Exception do
      Writeln('Error: ', E.Message);
  end;
  Readln;
end;

begin
  DisplayCertificates;
end.
