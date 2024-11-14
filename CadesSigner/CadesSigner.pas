unit CadesSigner;

interface

uses
  Windows,
  SysUtils,
  Classes,
  JwaWinCrypt,
  GostOIDs,
  Cades;

type
   T20Bytes = array[0..19] of Byte;  // SHA-1 hash is 20 bytes

  // �������� ����������� ��� ������������� � ���� ������ � ����������� ������������
  // FriendlyName - "������������" ���. ������ ���, �� ����� ���� ��� ������
  //                 ����� ���� ������ �� ������ �����������, ����� �������� �������������
  // Thumbprint - ���������� ������������� ("���������") �����������
  //              ������ ����������, � ��� ����� �� ������ �����������
  // Identifier - �������� ������������� thumbprint � ���� ����������������� ������
  // StartTime, EndTime - ����� �������� �����������
  TCertOption = record
    FriendlyName: string;
    Thumbprint: T20Bytes;
    Identifier: string;
    StartDateTime, EndDateTime: TDateTime;
  end;

  PCertOption = ^TCertOption;

  // ������ ���������� ���������� ������ ������� ����
  // ����� ���������� ����� ��������� ������ -
  // <��������� ������> [<��� ������ (GetLastError)>] <���������� �� ������(FormaMessage)>
  // ������ CryptoPro �� ���������� ���������� ��������� �� ������,
  // ��� ������ CryptoPro ����� ������ ���
  
  ECadesSignerException = class(Exception)
  private
    FErrorCode: DWORD;
  public
    constructor Create(const Message: string); reintroduce;
    property ErrorCode: DWORD read FErrorCode;
  end;

function GetCertificates(const Prefix: string): TList;

function GetUniqueSignatureFileName(const FileName: string): string;


procedure SignFile(
  const FilePath: string;
  const SigPath: string;
  const thumbprint: T20Bytes;
  const password: string);

procedure SignFileStr(
  const FilePath: string;
  const SigPath: string;
  const Identifier: string;
  const password: string);

implementation

type
   TBytes = array of Byte;

{ Error Handling }

const
  ERR_OPEN_STORE_FAILED  = '�� ������� ������� ��������� ������������.';
  ERR_CLOSE_STORE_FAILED  = '�� ������� ������� ��������� ������������.';
  ERR_GET_SUBJECT_FAILED = '�� ������� �������� "Subject" ��� �����������.';
  ERR_GET_THUMB_FAILED = '�� ������� �������� "Thumbprint" ��� �����������.';
  ERR_FIND_THUMB_FAILED = '�� ������� ����� ���������� �� "Thumbprint".';
  ERR_FAILED_TO_OPEN = '�� ������� ������� ����';
  ERR_FAILED_TO_READ = '�� ������� ��������� ����';
  ERR_FAILED_TO_WRITE = '�� ������� �������� ����';
  ERR_FAILED_TO_UNIQ = '�� ������� ������� ���������� ��� ��� ����� �������';
  ERR_FILE_SIGN_FAILED  = '�� ������� ��������� ����';
  ERR_GET_PROP_FAILED = '�� ������� �������� �������� ����������������';
  ERR_ACQ_CONETXT_FAILED = '�� ������� �������� �������� ����������������';
  ERR_SET_PIN_FAILED = '�� ������� ��������� ������ ��� ("���")';
  ERR_NOT_20_BYTES = '������ ����������� �������������� ��� �� ����� 20 ������';
  ERR_FAILED_TO_CONVERT_TILE = 'Failed to convert FILETIME to TDateTime';

constructor ECadesSignerException.Create(const Message: string);
var
  Msg: string;
begin
  FErrorCode := GetLastError;
  if FErrorCode <> 0 then
    Msg :=
      Format('%s [0x%s] %s',
      [Message, IntToHex(FErrorCode, 8), SysErrorMessage(FErrorCode)])
  else
    Msg := Message; // Use the original message if there's no error code.

  inherited Create(Msg);
end;

//  RaiseError
//  private
//  ������������ ��������� �� ������, ������� ����������
//  ���������
//     Message - const string
//     ��������� ������ (���� �� �������� ����)
//  noreturn
procedure RaiseError(const Message: string);
begin
  raise ECadesSignerException.Create(Message);
end;

{ T20Bytes helpers }

//  T20BytesToHexString
//  private
//  �������������� thumbprint � ������
//  ���������
//      const Value - thumbprint � ���� T20Bytes
//  ���������
//      ������ �������������������� �������� �������������
function T20BytesToHexString(const Value: T20Bytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := Low(Value) to High(Value) do
    Result := Result + IntToHex(Value[I], 2);
end;

//  HexStringToT20Bytes
//  private
//  �������������� ������ � thumbprint
//  ���������
//      const Hex - �������������������� �������� ������������� thumbprint
//  ���������
//      thumbprint � ���� T20Bytes
//  ���������� ECadesSignerException
//      ���� �� ������� ��������� �� ����� 40 ��������
function HexStringToT20Bytes(const Hex: string): T20Bytes;
var
  I: Integer;
begin
  if Length(Hex) <> 40 then  // 20 bytes * 2 hex digits per byte
    RaiseError(ERR_NOT_20_BYTES);

  for I := 0 to 19 do
    Result[I] := StrToInt('$' + Copy(Hex, (I * 2) + 1, 2));
end;

{ Certificate helpers }

//  FileTimeToDateTime
//  private
//  ������������ ����� � ������� TFileTime � TDateTime
//  ���������
//      const TFileTime - ��� ������������
//  ��������� TDateTime
//  ���������� ECadesSignerException
//      ���� ����������� �� �������

function FileTimeToDateTime(const FileTime: TFileTime): TDateTime;
var
  SystemTime: TSystemTime;
begin
  if FileTimeToSystemTime(FileTime, SystemTime) then
    Result := SystemTimeToDateTime(SystemTime)
  else
    raise Exception.Create(ERR_FAILED_TO_CONVERT_TILE);
end;


//  GetCertificateByThumbprint
//  private
//  ����� ����������� �� Thumbprint
//  ���������
//      const HCERTSTORE - ��������� ������������
//      const thumbprint - ������������, �� �������� ���� ����������
//  ���������
//      ����������
//      ����� !!! ���������� ���������� � ��������� ���������
//      ���� ��������� �������, ������� ����������� ����� �����������
//  ���������� ECadesSignerException
//      ���� �� ������� ����� ����������

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
//  ��������� OID ��������� ����������� �� �����������
//  ���������
//      const PCCERT_CONTEXT - ����������
//  ���������
//      OID ��������� ����������� (��. GostOIDs.pas)
//      ���� �������� ����������, ���������� ������ ������

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

//  SetPassword
//  private
//  ���������� ������
//  ���������
//      const PCCERT_CONTEXT - ����������
//      const Password - ������
//  ���������� ECadesSignerException
//      ���� �� ������� �������� ������ � ��������� ����������
//      ���� �� ������� �������� ������

procedure SetPassword(
  const pCert: PCCERT_CONTEXT;
  const Password: string);
var
  pProvKey: PCRYPT_KEY_PROV_INFO;
  dwProvKeyInfoSize: DWORD;
  dwKeytype: DWORD;
  hProvider: HCRYPTPROV;
begin
  pProvKey := nil;
  dwProvKeyInfoSize := 0;
  try
    if not CertGetCertificateContextProperty(
      pCert,
      CERT_KEY_PROV_INFO_PROP_ID,
      pProvKey,
      dwProvKeyInfoSize) then
      RaiseError(ERR_GET_PROP_FAILED);

    GetMem(pProvKey, dwProvKeyInfoSize);
    if not CertGetCertificateContextProperty(pCert,
      CERT_KEY_PROV_INFO_PROP_ID,
      pProvKey,
      dwProvKeyInfoSize) then
      RaiseError(ERR_GET_PROP_FAILED);

      if pProvKey^.dwKeySpec = AT_SIGNATURE then
        dwKeyType := PP_SIGNATURE_PIN
      else
        dwKeyType := PP_KEYEXCHANGE_PIN;

    if not CryptAcquireContextW(
      hProvider,
      pProvKey^.pwszContainerName,
      pProvKey^.pwszProvName,
      pProvKey^.dwProvType,
      CRYPT_MACHINE_KEYSET) then
      RaiseError(ERR_ACQ_CONETXT_FAILED);

    if not CryptSetProvParam(
      hProvider,
      dwKeyType,
      PBYTE(Password),
      0) then
      RaiseError(ERR_SET_PIN_FAILED);
  finally
    if Assigned(pProvKey) then
      FreeMem(pProvKey);
    end
end;

{ File helpers }

//  GetUniqueSignatureFileName
//  private
//  ���������� ���� � ����� � ��������
//  ��������
//    ������ ���������� � �����, ������� �����������, �� 'sig'
//    ���� ���������� ���, ��������� 'sig'
//    ���� ����� ���� ��� ����������, ��������� � ���������� �������� '1', '2', ...
//    ���� �� ��������� ���������� ����
//  ���������
//      const string FileName - ���� � �����, ������� �����������
//  ���������
//      string ���� � ����� � ��������
//  ���������� ECadesSignerException
//      ���� �� ������� ������� ���������� ���������� ��� ����� ������� (� ����� ...)

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
//  ������ ����������� ����� � ������ ����
//  ���������
//      const string FileName - ���� � �����
//  ���������
//      TBytes - ���������� �����
//  ���������� ECadesSignerException
//      ���� �� ������� ������ ����
//      ���� �� ������� ��������� ���������� �����

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
//  ������ ������� ���� � �����
//  ���� ���� ����������, �� ����������������
//  ���������
//      const string FileName - ���� � �����
//      const PByte Data - ��� ������
//      const integer Length - ������� �����
//  ���������� ECadesSignerException
//      ���� �� ������� ������� ����
//      ���� �� ������� �������� ���������� �����

procedure WriteFileContent(
  const FileName: string;
  const Data: PByte;
  const Length: integer);
var
  FileStream: TFileStream;
begin
  try
    FileStream := TFileStream.Create(FileName, fmCreate or fmShareExclusive);
  except
    on E: Exception do
    begin
      RaiseError(ERR_FAILED_TO_OPEN + ' "' + FileName + '": ' + E.Message);
      Exit;
    end;
  end;

  try
    if FileStream.Write(Data, Length) <> Length then
      RaiseError(ERR_FAILED_TO_WRITE + ' "' + FileName + '"');
  finally
    FileStream.Free;
  end;
end;

{ Certificate List Retrieval }

//  GetCertificates
// interface
//  �������� ������ ������������, OID ������� ������������� ��������� ��������
//  OID - �������������� ������������������ ���������
//  ��������, ������� ������ ����� '1.2.643', ���
//   1: ��� International Organization for Standardization(���).
//   2: ��������, ��� OID ���������� ������������-������ ���
//   643: ��� ������ - ������
//   ������� OID '1.2.643' ����� ��� ���������� ��������� ���������� � �����������,
//   ������� ����������� ������  ���� 34.11-2012/34.10-2012
//
//  ���������
//      const string Prefix - ������� OID
//  ���������
//      TList<TCertOption> - ������ �������� ������������
//      �������� ������ ��������� �����������, ����� ����������� ������
//  ���������� ECadesSignerException
//      ���� �� ������� ������ ��������� ������������
//      ���� �� ������� ������� ��������� ������������
//      ���� �� ��������� ��������� �����������

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
          RaiseError(ERR_GET_SUBJECT_FAILED);

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
      CertOptionPtr^.Identifier := T20BytesToHexString(CertOptionPtr^.Thumbprint);
      CertOptionPtr^.StartDateTime :=
        FileTimeToDateTime(TFileTime(pCertContext^.pCertInfo^.NotBefore));
      CertOptionPtr^.EndDateTime :=
        FileTimeToDateTime(TFileTime(pCertContext^.pCertInfo^.NotAfter));
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

{ File Signing }

//  SignFile
//  interface
//  ��������� ������� ��� ����������� �����, ��������� ������� ������� ����
//  ���� ������� ���� ����������, �� ����������������
//  ���������
//      const string FileName - ���� � �����
//      const string FileName - ���� � ����� � �������� (��������)
//      const sring Thumbprint - thumbprint, �� �������� ���� ����������
//      const string Password - ������; ���� ��� ���� �����, ����������� �� �����
//  ���������
//      string ���� � ����� � ��������
//  ���������� ECadesSignerException
//      ���� �� ������� ������ ����
//      ���� �� ������� ��������� ���������� �����
//      ���� �� ������� ������ ��������� ������������
//      ���� �� ������� ������� ����
//      ���� �� ������� �������� ���������� �����
//      ���� ���� �������� � �����������, ��������, �� ������� ������

procedure SignFile(
  const FilePath: string;
  const SigPath: string;
  const Thumbprint: T20Bytes;
  const Password: string);
var
  hStore: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  pSignedMessage: PCRYPT_DATA_BLOB;
  pChainContext: PCERT_CHAIN_CONTEXT;
  Certs: TList;
  SignPara: CRYPT_SIGN_MESSAGE_PARA;
  CadesSignPara: CADES_SIGN_PARA;
  Para: CADES_SIGN_MESSAGE_PARA;
  FileContent: TBytes;
  ChainPara: CERT_CHAIN_PARA;
  i: Integer;
  pbToBeSigned: PByte;
  cbToBeSigned: DWORD;

  pChainElement: PCERT_CHAIN_ELEMENT;
  ppChainElement: ^PCERT_CHAIN_ELEMENT;
  ppSignCertContext: ^PCERT_CONTEXT;
begin
  hStore := nil;
  pCertContext := nil;
  pSignedMessage := nil;
  pChainContext := nil;
  Certs := TList.Create;
  try
    FillChar(SignPara, SizeOf(SignPara), 0);
    FillChar(CadesSignPara, SizeOf(CadesSignPara), 0);
    FillChar(Para, SizeOf(Para), 0);
    FillChar(ChainPara, SizeOf(ChainPara), 0);

    hStore := CertOpenSystemStore(0, 'MY');
    if hStore = nil then
      RaiseError(ERR_OPEN_STORE_FAILED);

    // Signer certificate
    pCertContext := GetCertificateByThumbprint(hStore, Thumbprint);

    // The data to be signed
    FileContent := ReadFileContent(FilePath);
    pbToBeSigned := Pointer(FileContent);
    cbToBeSigned := Length(FileContent);

    // Initialize sign parameters
    // Standard wincert
    SignPara.cbSize := SizeOf(CRYPT_SIGN_MESSAGE_PARA);
    SignPara.dwMsgEncodingType := X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;
    SignPara.pSigningCert := nil;
    SignPara.pSigningCert := pCertContext;
    SignPara.HashAlgorithm.pszObjId := PAnsiChar(GetHashOid(pCertContext));

    // Cades
    CadesSignPara.dwSize := SizeOf(CadesSignPara);
    CadesSignPara.dwCadesType := CADES_BES;

    // Wrapper
    Para.dwSize := SizeOf(CADES_SIGN_MESSAGE_PARA);
    Para.pSignMessagePara := @SignPara;
    Para.pCadesSignPara := @CadesSignPara;

    // Get certificate chain
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
      if pChainContext.rgpChain^.cElement > 1 then
      begin
        SignPara.cMsgCert := pChainContext.rgpChain^.cElement -1;
        GetMem(SignPara.rgpMsgCert, SignPara.cMsgCert * SizeOf(PCERT_CONTEXT));

        ppChainElement := pChainContext.rgpChain^.rgpElement;
        ppSignCertContext := SignPara.rgpMsgCert;

        for i := 0 to SignPara.cMsgCert - 1 do
        begin
          pChainElement := ppChainElement^;
          ppSignCertContext^ := pChainElement^.pCertContext;
          Inc(ppChainElement);
          Inc(ppSignCertContext);
        end;
      end;
    end;


    if password <> '' then
      SetPassword(pCertContext, Password);

    // Create signed message
    if not CadesSignMessage(
      @Para,
      false,
      1,
      @pbToBeSigned,
      @cbToBeSigned,
      @pSignedMessage) then
    RaiseError(ERR_FILE_SIGN_FAILED);

   // Save the signed message
   WriteFileContent(
    SigPath,
    pSignedMessage^.pbData,
    pSignedMessage^.cbData);

  finally
    if Assigned(SignPara.rgpMsgCert) then
      FreeMem(SignPara.rgpMsgCert);
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

//  SignFileStr
//  interface
//  ��������� ������� ��� ����������� �����, ��������� ������� ������� ����
//  ���� ������� ���� ����������, �� ����������������
//  ���������
//      const string FileName - ���� � �����
//      const string FileName - ���� � ����� � �������� (��������)
//      const string Identifier - ������������, �� �������� ���� ����������
//                                (thumbprint � ���� ������������������ ������)
//      const string Password - ������; ���� ��� ���� �����, ����������� �� �����
//  ���������
//      string ���� � ����� � ��������
//  ���������� ECadesSignerException
//      ���� �� ������� ������ ����
//      ���� �� ������� ��������� ���������� �����
//      ���� �� ������� ������ ��������� ������������
//      ���� �� ������� ������� ����
//      ���� �� ������� �������� ���������� �����
//      ���� ���� �������� � �����������, ��������, �� ������� ������

procedure SignFileStr(
  const FilePath: string;
  const SigPath: string;
  const Identifier: string;
  const Password: string);
var
  Thumbprint: T20Bytes;
begin
   Thumbprint := HexStringToT20Bytes(Identifier);
   SignFile(FilePath, SigPath, Thumbprint, Password);
end;

end.

