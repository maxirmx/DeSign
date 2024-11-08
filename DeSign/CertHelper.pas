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

  // �������� ����������� ��� ������������� � ���� ������ � ����������� ������������
  // FriendlyName - "������������" ���. ������ ���, �� ����� ���� ��� ������
  //                 ����� ���� ������ �� ������ �����������, ����� �������� �������������
  // Thumbprint - ���������� ������������� ("���������") �����������
  //              ������ ����������, � ��� ����� �� ������ �����������
  TCertOption = record
    FriendlyName: string;
    Thumbprint: T20Bytes;
  end;

  PCertOption = ^TCertOption;

  // ������ ���������� ���������� ������ ������� ����
  // ����� ���������� ����� ��������� ������ -
  // <��������� ������> [<��� ������ (GetLastError)>] <���������� �� ������(FormaMessage)>
  ECertificateException = class(Exception);

function GetCertificates(const Prefix: string): TList;
function SignFile(const FilePath: string; const Thumbprint: T20Bytes): string;


implementation

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
  // �� ������ ���������, ����� ��� �������� race condition �����
  ERR_FILE_EXISTS = '���� ������� � ����� ������ ��� ����������: ';
  ERR_FILE_SIGN_FAILED  = '�� ������� ��������� ����';

//  RaiseError
//  private
//  ������������ ��������� �� ������, ������� ����������
//  ���������
//     Message - const string
//     ��������� ������ (���� �� �������� ����)
//  noreturn
procedure RaiseError(const Message: string);
var
  ErrorCode: DWORD;
  FullMessage: string;
begin
  ErrorCode := GetLastError;
  FullMessage := Format(
        '%s [0x%s] %s',
        [Message, IntToHex(ErrorCode, 8), SysErrorMessage(ErrorCode)]);
  raise Exception.Create(FullMessage);
end;

{ Certificate helpers }


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
//  ���������� ECertificateException
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
//  ���������� ECertificateException
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
//  ���������� ECertificateException
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
//  ���������
//      const string FileName - ���� � �����
//      const TByte Data - ��� ������
//  ���������� ECertificateException
//      ���� ���� � ����� ������ ��� ����������
//      ���� �� ������� ������� ����
//      ���� �� ������� �������� ���������� �����

procedure WriteFileContent(const FileName: string; const Data: PByte; const L: integer);
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
    if FileStream.Write(Data, L) <> L then
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
//  ���������� ECertificateException
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


function SignFile(const FilePath: string; const Thumbprint: T20Bytes): string;
var
  hStore: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  pSignedMessage: PCRYPT_DATA_BLOB;
  pChainContext: PCERT_CHAIN_CONTEXT;
  Certs: TList;
  SignPara: CRYPT_SIGN_MESSAGE_PARA;     // Msg
  CadesSignPara: CADES_SIGN_PARA;        // MsgAdd
  Para: CADES_SIGN_MESSAGE_PARA;         // MsgEx
  FileContent: TBytes;
  ChainPara: CERT_CHAIN_PARA;
  i: Integer;
  SignatureFileName: string;
  pbToBeSigned: PByte;
  cbToBeSigned: DWORD;


  pChainElement: PCERT_CHAIN_ELEMENT;
  ppChainElement: ^PCERT_CHAIN_ELEMENT;
  pChainCertContext: PCCERT_CONTEXT;

  //pSignCertContext: PCERT_CONTEXT;
  ppSignCertContext: ^PCERT_CONTEXT;
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

    // Signer certificate
    pCertContext := GetCertificateByThumbprint(hStore, Thumbprint);

    // Signature file name
    SignatureFileName := GetUniqueSignatureFileName(FilePath);

    // The data to be signed
    FileContent := ReadFileContent(FilePath);
    pbToBeSigned := Pointer(FileContent);
    cbToBeSigned := Length(FileContent);

    // Initialize sign parameters
    // Standard wincert
    FillChar(SignPara, SizeOf(SignPara), 0);
    SignPara.cbSize := SizeOf(CRYPT_SIGN_MESSAGE_PARA);
    SignPara.dwMsgEncodingType := X509_ASN_ENCODING or PKCS_7_ASN_ENCODING;
    SignPara.pSigningCert := nil;
    SignPara.pSigningCert := pCertContext;
    SignPara.HashAlgorithm.pszObjId := PAnsiChar(GetHashOid(pCertContext));

    // Cades
    FillChar(CadesSignPara, SizeOf(CadesSignPara), 0);
    CadesSignPara.dwSize := SizeOf(CadesSignPara);
    CadesSignPara.dwCadesType := CADES_BES;

    // Wrapper
    FillChar(Para, SizeOf(Para), 0);
    Para.dwSize := SizeOf(CADES_SIGN_MESSAGE_PARA);
    Para.pSignMessagePara := @SignPara;
    Para.pCadesSignPara := @CadesSignPara;


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
      if pChainContext.rgpChain^.cElement > 1 then
      begin
        writeln('Elements in the chain: ', pChainContext.rgpChain^.cElement);

        SignPara.cMsgCert := pChainContext.rgpChain^.cElement -1;
        GetMem(SignPara.rgpMsgCert, SignPara.cMsgCert * SizeOf(PCERT_CONTEXT));

        writeln('  ==> Chain certificates in SignPara: ', SignPara.cMsgCert);
        //SignPara.cMsgCert := 0;
        ppChainElement := pChainContext.rgpChain^.rgpElement;
        ppSignCertContext := SignPara.rgpMsgCert;

        for i := 0 to SignPara.cMsgCert - 1 do
        begin
          pChainElement := ppChainElement^;
          //pSignCertContext := ppSignCertContext^;
          writeln('CERT_CHAIN_ELEMENT ', i, ' cbSize=', pChainElement^.cbSize);
          pChainCertContext := pChainElement^.pCertContext;
          writeln('     CHAIN_CERT_CONTEXT hCertStore=', Format('%p', [pChainCertContext^.hCertStore]));
          ppSignCertContext^ := pChainElement^.pCertContext;
          Inc(ppChainElement);
          Inc(ppSignCertContext);
        end;
        //SignPara.cMsgCert := 0;
      end;
    end;

    // Add certificates (without root) to message
{    if Certs.Count > 0 then
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
 }

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
    SignatureFileName,
    pSignedMessage^.pbData,
    pSignedMessage^.cbData);

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
  Result := SignatureFileName;
end;
end.

