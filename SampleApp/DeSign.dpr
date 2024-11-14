program DeSign;

{$APPTYPE CONSOLE}

uses
  Windows,
  SysUtils,
  Classes,
  CadesSigner,
  JwaWinCrypt;

procedure PrintTableHeader;
begin
  WriteLn(Format('%-5s%-30s%s', ['�', 'Friendly Name/Subject)', 'Thumbprint']));
  WriteLn(
    StringOfChar('-', 5) + ' ' +
    StringOfChar('-', 30) + ' ' +
    StringOfChar('-', 40));
end;

procedure PrintTableRow(Index: Integer; const Cert: TCertOption);
begin
  // Print the main row with the index, friendly name, and ThumbprintStr
  WriteLn(Format('%-5d%-30s%-30s', [
    Index + 1,
    Cert.FriendlyName,
    Cert.ThumbprintStr
  ]));

  // Print StartDateTime and EndDateTime on the next line, aligned with FriendlyName
  WriteLn(Format('%-5s%-20s%-20s', [
    '',  // Blank space for alignment
    '��������� �: ' + DateTimeToStr(Cert.StartDateTime),
    ' ��: ' + DateTimeToStr(Cert.EndDateTime)
  ]));
end;

function PromptUserToSelectCertificate(const Certificates: TList): Integer;
var
  ChoiceStr: string;
  Choice: Integer;
begin
  Result := -1; // Default invalid result
  while Result = -1 do
  begin
    Write('�������� ���������� �� ������ � ������� <ENTER> ');
    ReadLn(ChoiceStr);

    try
      Choice := StrToInt(ChoiceStr);
      if (Choice >= 1) and (Choice <= Certificates.Count) then
        Result := Choice
      else
        WriteLn(Format(
            '�������� ����. ����������, ������� ����� �� 1 �� %d.',
            [Certificates.Count]));
    except
      on E: EConvertError do
        WriteLn(Format(
            '�������� ����. ����������, ������� ����� �� 1 �� %d.',
            [Certificates.Count]));
    end;
  end;
end;


function PromptUserToEnterFileName: string;
var
  FileName: string;
begin
  Write('������� ���� � �����, ������� ���������� ��������� � ������� <ENTER> ');
  ReadLn(FileName);
  Result := FileName;
end;

var
  Certificates: TList;
  i, SelectedIndex: Integer;
  SelectedCert: TCertOption;
  fileName: string;
  sigFileName: string;
begin
  Certificates := nil;
  try
    SetConsoleOutputCP(1251);
    SetConsoleCP(1251);

    Certificates := GetCertificates('1.2.643'); // ��������.���.������ = ����

    if Certificates.Count > 0 then
    begin
      WriteLn('����������� � ���������� ���������� �� ���������� ����');
      PrintTableHeader;

      for i := 0 to Certificates.Count - 1 do
        PrintTableRow(i, TCertOption(Certificates[i]^));

      SelectedIndex := PromptUserToSelectCertificate(Certificates);
      SelectedCert := TCertOption(Certificates[SelectedIndex - 1]^);
      fileName := PromptUserToEnterFileName;
      sigFileName := GetUniqueSignatureFileName(fileName);
      SignFileStr(fileName, sigFileName, SelectedCert.ThumbprintStr, '');
      Writeln('������� ��������� � ���� ', sigFileName);
    end
    else
      WriteLn('�� ������� �� ������ ����������� � ���������� ���������� �� ����')
  except
    on E: Exception do
      WriteLn('������: ', E.Message)
  end;
  if Certificates <> nil then
    Certificates.Free;
  WriteLn('������� <ENTER> ��� ����������...');
  Readln;
end.

