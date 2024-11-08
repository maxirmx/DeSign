program DeSign;

{$APPTYPE CONSOLE}

uses
  Windows,
  SysUtils,
  Classes,
  CadesSigner,
  JwaWinCrypt;
  //AdesConstants;

procedure PrintHex(const Data: array of Byte);
var
  i: Integer;
begin
  for i := Low(Data) to High(Data) do
    Write(Format('%.2x', [Data[i]]));
end;

procedure PrintTableHeader;
begin
  WriteLn(Format('%-5s%-30s%s', ['№', 'Friendly Name/Subject)', 'Thumbprint']));
  WriteLn(StringOfChar('-', 5) + ' ' + StringOfChar('-', 30) + ' ' + StringOfChar('-', 40));
end;

procedure PrintTableRow(Index: Integer; const Cert: TCertOption);
begin
  Write(Format('%-5d%-30s', [Index + 1, Cert.FriendlyName]));
  PrintHex(Cert.Thumbprint);
  WriteLn;
end;

function PromptUserToSelectCertificate(const Certificates: TList): Integer;
var
  ChoiceStr: string;
  Choice: Integer;
begin
  Result := -1; // Default invalid result
  while Result = -1 do
  begin
    Write('Выберите сертификат по номеру и нажмите <ENTER> ');
    ReadLn(ChoiceStr);

    try
      Choice := StrToInt(ChoiceStr);
      if (Choice >= 1) and (Choice <= Certificates.Count) then
        Result := Choice
      else
        WriteLn(Format(
            'Неверный ввод. Пожалуйста, введите число от 1 до %d.',
            [Certificates.Count]));
    except
      on E: EConvertError do
        WriteLn(Format(
            'Неверный ввод. Пожалуйста, введите число от 1 до %d.',
            [Certificates.Count]));
    end;
  end;
end;


function PromptUserToEnterFileName: string;
var
  FileName: string;
begin
  Write('Введите путь к файлу, который необходимо подписать и нажмите <ENTER> ');
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
  try
    Certificates := GetCertificates('1.2.643'); // Стандарт.ИСО.Россия = ГОСТ

    if Certificates.Count > 0 then
    begin
      WriteLn('Сертификаты с поддержкой шифрования по алгоритмам ГОСТ');
      PrintTableHeader;

      for i := 0 to Certificates.Count - 1 do
        PrintTableRow(i, TCertOption(Certificates[i]^));

      SelectedIndex := PromptUserToSelectCertificate(Certificates);
      SelectedCert := TCertOption(Certificates[SelectedIndex - 1]^);
      fileName := PromptUserToEnterFileName;
      sigFileName := SignFile(fileName, SelectedCert.Thumbprint, '');
      Writeln('Подпись сохранена в файл ', sigFileName);
    end
    else
      WriteLn('Не найдено ни одного сертификата с поддержкой шифрования по ГОСТ')
  except
    on E: Exception do
      WriteLn('Ошибка: ', E.Message)
  end;
  WriteLn('Нажмите <ENTER> для завершения...');
  Readln;
end.

