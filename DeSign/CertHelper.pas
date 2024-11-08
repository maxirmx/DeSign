unit CertHelper;

interface

uses
  Windows,
  SysUtils,
  Classes,
  JwaWinCrypt,
  GostOIDs,
  Cades;

type
   TBytes = array of Byte;
   T20Bytes = array[0..19] of Byte;  // SHA-1 hash is 20 bytes

  // Описание сертификата для использовании в меню выбора с последующим запоминанием
  // FriendlyName - "человеческое" имя. Обычно ФИО, но может быть что угодно
  //                 Может быть разным на разных компьютерах, может меняться пользователем
  // Thumbprint - уникальный идентификатор ("отпечаток") сертификата
  //              всегда одинаковый, в том числе на разных компьютерах
  TCertOption = record
    FriendlyName: string;
    Thumbprint: T20Bytes;
  end;

  PCertOption = ^TCertOption;

  // Модуль использует исключения только данного типа
  // Текст исключения имеет следующий формат -
  // <Сообщение модуля> [<Код ошибки (GetLastError)>] <Информация об ошибке(FormaMessage)>
  ECertificateException = class(Exception);

function GetCertificates(const Prefix: string): TList;
procedure SignFile(const FilePath: string; const Thumbprint: T20Bytes);


implementation

{ Error Handling }

const
  ERR_OPEN_STORE_FAILED  = 'Не удалось открыть хранилище сертификатов.';
  ERR_CLOSE_STORE_FAILED  = 'Не удалось закрыть хранилище сертификатов.';
  ERR_GET_SUBJECT_FAILED = 'Не удалось получить "Subject" для сертификата.';
  ERR_GET_THUMB_FAILED = 'Не удалось получить "Thumbprint" для сертификата.';
  ERR_FIND_THUMB_FAILED = 'Не удалось найти сертификат по "Thumbprint".';
  ERR_FAILED_TO_OPEN = 'Не удалось открыть файл';
  ERR_FAILED_TO_READ = 'Не удалось прочитать файл';
  ERR_FAILED_TO_WRITE = 'Не удалось записать файл';
  ERR_FAILED_TO_UNIQ = 'Не удалось создать уникальное имя для файла подписи';
  // Не должно случиться, разве что безумный race condition будет
  ERR_FILE_EXISTS = 'Файл подписи с таким именем уже существует: ';
  ERR_FILE_SIGN_FAILED  = 'Не удалось подписать файл';

//  RaiseError
//  private
//  Сформировать сообщение об ошибке, поднять исключение
//  Параметры
//     Message - const string
//     Сообщение модуля (одна из констант выше)
//  noreturn
procedure RaiseError(const Message: string);
var
  ErrorCode: DWORD;
  ErrorMsg: PChar;
  FullMessage: string;
begin
  ErrorCode := GetLastError;
  FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER or
      FORMAT_MESSAGE_FROM_SYSTEM or
      FORMAT_MESSAGE_IGNORE_INSERTS,
      nil,
      ErrorCode,
      LANG_NEUTRAL,
      @ErrorMsg,
      0,
      nil);
  FullMessage := Format('%s [%s] %s', [Message, IntToHex(ErrorCode, 8), ErrorMsg]);
  LocalFree(HLOCAL(ErrorMsg));
  raise Exception.Create(FullMessage);
end;

{ Certificate helpers }


//  GetCertificateByThumbprint
//  private
//  Поиск сертификата по Thumbprint
//  Параметры
//      const HCERTSTORE - хранилище сертификатов
//      const thumbprint - thumbprint, по которому ищем
//  Результат
//      сертификат
//      ВАЖНО !!! Сертификат существует в контексте хранилища
//      Если хранилище закрыть, ресурсы сертификата будут освобождены
//  Исключение ECertificateException
//      Если не удалось найти сертификат

function GetCertificateByThumbprint(
    const hStore: HCERTSTORE;
    const thumbprint: T20Bytes): PCCERT_CONTEXT;
var
  pCertContext: PCCERT_CONTEXT;
  hashBlob: CRYPT_HASH_BLOB;
begin
  hashBlob.cbData := Length(thumbprint);
  hashBlob.pbData := @thumbprint[0];

  pCertContext := CertFindCertificateInStore(
      hStore,
      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0,
      CERT_FIND_HASH,
      @hashBlob,
      nil);
  if pCertContext = nil then
    RaiseError(ERR_FIND_THUMB_FAILED);

  Result := pCertContext;
end;


//  GetHashOid
//  private
//  Получение OID алгоритма хеширования по сертификату
//  Параметры
//      const PCCERT_CONTEXT - сертификат
//  Результат
//      OID алгоритме хеширования (см. GostOIDs.pas)
//      Если алгоритм неизвестен, возвращает пустую строку

function GetHashOid(const pCert: PCCERT_CONTEXT): string;
var
  pKeyAlg: string;
begin
  pKeyAlg := string(pCert.pCertInfo.SubjectPublicKeyInfo.Algorithm.pszObjId);

  if pKeyAlg = CP_GOST_R3410EL then
    Result := CP_GOST_R3411
  else if pKeyAlg = CP_GOST_R3410_12_256 then
    Result := CP_GOST_R3411_12_256
  else if pKeyAlg = CP_GOST_R3410_12_512 then
    Result := CP_GOST_R3411_12_512
  else
    Result := '';
end;

{ File helpers }

//  GetUniqueSignatureFileName
//  private
//  Вычисление пути к файлу с подписью
//  Алгоритм
//    Меняем расширение к файлу, который подписываем, на 'sig'
//    Если расширения нет, добавляем 'sig'
//    Если такой файл уже существует, добавляем к расширению суффиксы '1', '2', ...
//    пока не получится уникальный путь
//  Параметры
//      const string FileName - путь к файлу, который подписываем
//  Результат
//      string путь к файлу с подписью
//  Исключение ECertificateException
//      Если не удалось создать уникальное расширение для файла подписи (а вдруг ...)

function GetUniqueSignatureFileName(const FileName: string): string;
var
  LastDot: Integer;
  BaseName, Extension, NewFileName: string;
  Counter: Integer;
begin
  LastDot := LastDelimiter('.', FileName);

  if LastDot = 0 then
    BaseName := FileName
  else
    BaseName := Copy(FileName, 1, LastDot - 1);

  Extension := '.sig';
  NewFileName := BaseName + Extension;
  Counter := 1;

  while FileExists(NewFileName) do
  begin
    if Counter = MaxInt then
      RaiseError(ERR_FAILED_TO_UNIQ);
    NewFileName := BaseName + Extension + IntToStr(Counter);
    Inc(Counter);
  end;

  Result := NewFileName;
end;

//  ReadFileContent
//  private
//  Чтение содержимого файла в массив байт
//  Параметры
//      const string FileName - путь к файлу
//  Результат
//      TBytes - содержимое файла
//  Исключение ECertificateException
//      Если не удалось отрыть файл
//      Если не удалось прочитать содержимое файла
function ReadFileContent(const FilePath: string): TBytes;
var
  FileStream: TFileStream;
  FileSize: Integer;
begin
  if not FileExists(FilePath) then
    RaiseError(ERR_FAILED_TO_OPEN + '"' + FilePath + '"');

  FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
  try
    FileSize := FileStream.Size;
    SetLength(Result, FileSize);
    if FileStream.Read(Result[0], FileSize) <> FileSize then
      RaiseError(ERR_FAILED_TO_READ + '"' + FilePath + '"');
  finally
    FileStream.Free;
  end;
end;

//  WriteFileContent
//  private
//  Запись массива байт в файла
//  Параметры
//      const string FileName - путь к файлу
//      const TByteы Data - что писать
//  Исключение ECertificateException
//      Если файл с таким именем уже существует
//      Если не удалось создать файл
//      Если не удалось записать содержимое файла

procedure WriteFileContent(const FileName: string; const Data: TBytes);
var
  FileStream: TFileStream;
begin
  if FileExists(FileName) then
    RaiseError(ERR_FILE_EXISTS + ' "' + FileName + '"');

  try
    FileStream := TFileStream.Create(FileName, fmCreate or fmShareExclusive);
  except
    on E: Exception do
    begin
      RaiseError(ERR_FAILED_TO_OPEN + ' "' + FileName + '"');
      Exit;
    end;
  end;

  try
    if FileStream.Write(Data[0], Length(Data)) <> Length(Data) then
      RaiseError(ERR_FAILED_TO_WRITE + ' "' + FileName + '"');
  finally
    FileStream.Free;
  end;
end;

{ Certificate List Retrieval }

//  GetCertificates
// interface
//  Получить список сертификатов, OID которых соответствует заданному префиксу
//  OID - идентификатора криптографического алгоритма
//  Вероятно, префикс всегда будет '1.2.643', где
//   1: код International Organization for Standardization(ИСО).
//   2: означает, что OID разработан организацией-членом ИСО
//   643: Код страны - Россия
//   Префикс OID '1.2.643' имеют все российские алгоритмы шифрования и хеширования,
//   напрмер применяемые сейчас  ГОСТ 34.11-2012/34.10-2012
//
//  Параметры
//      const string Prefix - префикс OID
//  Результат
//      TList<TCertOption> - список описаний сертификатов
//      Элементы списка создаются динамически, нужно освобождать память
//  Исключение ECertificateException
//      Если не удалось отрыть хранилище сертификатов
//      Если не удалось закрыть хранилище сертификатов
//      Если не прочитать аттрибуты сертификата

function GetCertificates(const Prefix: string): TList;
var
  Res: TList;
  hStoreHandle: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  AlgorithmId: string;
  FriendlyName: array[0..255] of AnsiChar;
  Sha1Thumbprint: T20Bytes;
  Size: DWORD;
  CertOptionPtr: PCertOption;
begin
  Res := TList.Create;

  hStoreHandle := CertOpenSystemStore(0, 'MY');
  if hStoreHandle = nil then
    RaiseError(ERR_OPEN_STORE_FAILED);

  try
    pCertContext := nil;
    while True do
    begin
      pCertContext := CertEnumCertificatesInStore(hStoreHandle, pCertContext);
      if pCertContext = nil then
        Break;

      AlgorithmId := string(pCertContext^.pCertInfo^.SignatureAlgorithm.pszObjId);
      if Pos(Prefix, AlgorithmId) <> 1 then
        Continue;

      if CertGetNameStringA(
          pCertContext,
          CERT_NAME_FRIENDLY_DISPLAY_TYPE,
          0,
          nil,
          FriendlyName,
          SizeOf(FriendlyName)) = 0 then
      begin
        if CertGetNameStringA(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nil,
            FriendlyName,
            SizeOf(FriendlyName)) = 0 then
        begin
          RaiseError(ERR_GET_SUBJECT_FAILED);
        end;
      end;

      Size := SizeOf(Sha1Thumbprint);
      if not CertGetCertificateContextProperty(
          pCertContext,
          CERT_HASH_PROP_ID,
          @Sha1Thumbprint,
          Size) then
      begin
        RaiseError(ERR_GET_THUMB_FAILED)
      end;

      New(CertOptionPtr);
      CertOptionPtr^.FriendlyName := string(FriendlyName);
      Move(Sha1Thumbprint[0], CertOptionPtr^.Thumbprint[0], Size);
      Res.Add(CertOptionPtr);
    end;
  except
    on E: Exception do
    begin
      CertCloseStore(hStoreHandle, 0);
      raise;
    end;
  end;

  if not CertCloseStore(hStoreHandle, 0) then
    RaiseError(ERR_CLOSE_STORE_FAILED);

  Result := Res;
end;


procedure SignFile(const FilePath: string; const Thumbprint: T20Bytes);
var
  hStore: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  pSignedMessage: PCRYPT_DATA_BLOB;
  pChainContext: PCCERT_CHAIN_CONTEXT;
  Certs: TList;
  SignPara: CRYPT_SIGN_MESSAGE_PARA;
  CadesSignPara: CADES_SIGN_PARA;
  Para: CADES_SIGN_MESSAGE_PARA;
  FileContent: TBytes;
  ChainPara: CERT_CHAIN_PARA;
  i: Integer;
  SignatureFileName: string;
  pbToBeSigned: PByte;
  cbToBeSigned: DWORD;
  pElement: PCERT_CHAIN_ELEMENT;
  item: CERT_CONTEXT;
begin
  hStore := nil;
  pCertContext := nil;
  pSignedMessage := nil;
  pChainContext := nil;
  Certs := TList.Create;
  try
    hStore := CertOpenSystemStore(0, 'MY');
    if hStore = nil then
      RaiseError(ERR_OPEN_STORE_FAILED);

    pCertContext := GetCertificateByThumbprint(hStore, Thumbprint);
    SignatureFileName := GetUniqueSignatureFileName(FilePath);
    FileContent := ReadFileContent(FilePath);

    // Initialize sign parameters
    FillChar(SignPara, SizeOf(SignPara), 0);
    SignPara.cbSize := SizeOf(SignPara);
    SignPara.dwMsgEncodingType := X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;
    SignPara.pSigningCert := pCertContext;
    SignPara.HashAlgorithm.pszObjId := PAnsiChar(GetHashOid(pCertContext));

    FillChar(CadesSignPara, SizeOf(CadesSignPara), 0);
    CadesSignPara.dwSize := SizeOf(CadesSignPara);
    CadesSignPara.dwCadesType := CADES_BES;

    FillChar(Para, SizeOf(Para), 0);
    Para.dwSize := SizeOf(Para);
    Para.pSignMessagePara := @SignPara;
    Para.pCadesSignPara := nil; //@CadesSignPara;

    // Prepare the data to be signed
    pbToBeSigned := @FileContent[0];
    cbToBeSigned := Length(FileContent);

    // Get certificate chain
    FillChar(ChainPara, SizeOf(ChainPara), 0);
    ChainPara.cbSize := SizeOf(ChainPara);


    if CertGetCertificateChain(
      0,
      pCertContext,
      nil,
      nil,
      @ChainPara,
      0,
      nil,
      @pChainContext) then
    begin
      pElement := pChainContext.rgpChain^.rgpElement^;
      for i := 0 to pChainContext.rgpChain^.cElement - 2 do
      begin
//        Certs.Add(pChainContext.rgpChain^.rgpElement[i]^.pCertContext);
        Certs.Add(pElement^.pCertContext);
        Inc(pElement);
      end;
    end;

    // Add certificates (without root) to message
    if Certs.Count > 0 then
    begin
      SignPara.cMsgCert := Certs.Count;
      GetMem(SignPara.rgpMsgCert, Certs.Count * SizeOf(CERT_CONTEXT));
      //SignPara.rgpMsgCert := @Certs.Items;
      for i := 0 to Certs.Count - 1 do
      begin
    // Get a pointer to the CERT_CONTEXT
    item := PCERT_CONTEXT(Certs.Items[i])^;

    // Move each CERT_CONTEXT to the allocated memory using Inc
    Move(item, SignPara.rgpMsgCert^, SizeOf(CERT_CONTEXT));

    // Increment the pointer to the next CERT_CONTEXT in the allocated memory
    Inc(SignPara.rgpMsgCert);
    end;
    end;

    // Create signed message
    if not CadesSignMessage(@Para, false, 1, pbToBeSigned, cbToBeSigned, @pSignedMessage) then
    begin
      RaiseError(ERR_FILE_SIGN_FAILED);
    end;

    // Save the signed message
{    WriteFileContent(SignatureFileName, pSignedMessage^.pbData);
    Writeln('Signature was saved successfully');
  }
  finally
    if pChainContext <> nil then
      CertFreeCertificateChain(pChainContext);
    if pSignedMessage <> nil then
      CadesFreeBlob(pSignedMessage);
    if pCertContext <> nil then
      CertFreeCertificateContext(pCertContext);
    if hStore <> nil then
      CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
    Certs.Free;
  end;
end;
end.

