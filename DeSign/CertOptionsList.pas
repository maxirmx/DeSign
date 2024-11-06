unit CertOptionsList;

interface

uses
  SysUtils,
  Windows,
  JwaWinCrypt;

type
  TByteArray = array of Byte;

  TCertOption = record
    FriendlyName: string;
    Thumbprint: TByteArray;
  end;

  TCertOptionsList = class
  private
    FCerts: array of TCertOption;
    FCount: Integer;
  public
    constructor Create;
    procedure AddCertOption(
      const FriendlyName: string;
      const Thumbprint: TByteArray);
    function GetCertOption(Index: Integer): TCertOption;
    function GetCertCount: Integer;
  end;

function GetCertificates(const Prefix: string): TCertOptionsList;

implementation

{ Error Handling }

  procedure RaiseError(const Message: string);
  var
    ErrorCode: DWORD;
    ErrorMsg: PChar;
    FullMessage: string;
  begin
    ErrorCode := GetLastError;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER or
        FORMAT_MESSAGE_FROM_SYSTEM or
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nil,
        ErrorCode,
        LANG_NEUTRAL,
        @ErrorMsg,
        0,
        nil);
    FullMessage := Format('%s [%d] %s', [Message, ErrorCode, ErrorMsg]);
    LocalFree(HLOCAL(ErrorMsg));
    raise Exception.Create(FullMessage);
  end;

{ TCertOptions }

  constructor TCertOptionsList.Create;
  begin
    inherited Create;
    FCount := 0;
    SetLength(FCerts, 0);
  end;

  procedure TCertOptionsList.AddCertOption(
      const FriendlyName: string;
      const Thumbprint: TByteArray);
  begin
    if Length(FCerts) <= FCount then
      SetLength(FCerts, FCount + 1);

    FCerts[FCount].FriendlyName := FriendlyName;
    FCerts[FCount].Thumbprint := Thumbprint;
    Inc(FCount);
  end;

  function TCertOptionsList.GetCertOption(Index: Integer): TCertOption;
  begin
    if (Index >= 0) and (Index < FCount) then
      Result := FCerts[Index]
    else
      raise Exception.CreateFmt('Index %d out of bounds', [Index]);
  end;

  function TCertOptionsList.GetCertCount: Integer;
  begin
    Result := FCount;
  end;

{ Certificate Retrieval }  

  function GetCertificates(const Prefix: string): TCertOptionsList;
  var
    hStoreHandle: HCERTSTORE;
    pCertContext: PCCERT_CONTEXT;
    AlgorithmId: string;
    FriendlyName: array[0..255] of Char;
    FriendlyNameStr: string;
    Sha1Thumbprint: TByteArray;
    Size: DWORD;
  begin
    Result := TCertOptionsList.Create;

    hStoreHandle := CertOpenSystemStore(0, 'MY');
    if hStoreHandle = nil then
      RaiseError('Не удалось открыть хранилище сертификатов.');

    try
      pCertContext := nil;
      while True do
      begin
        pCertContext := CertEnumCertificatesInStore(hStoreHandle, pCertContext);
        if pCertContext = nil then
          Break;

        AlgorithmId := pCertContext^.pCertInfo^.SignatureAlgorithm.pszObjId;
        if Pos(Prefix, AlgorithmId) <> 1 then
          Continue;

        // Get the friendly name of the certificate
        if (CertGetNameString(
                pCertContext,
                CERT_NAME_FRIENDLY_DISPLAY_TYPE,
                0,
                nil,
                FriendlyName,
                SizeOf(FriendlyName)) = 0)
            or (FriendlyName[0] = #0) then
        begin
          if CertGetNameString(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                nil,
                FriendlyName,
                SizeOf(FriendlyName)) = 0 then
            RaiseError('Не удалось получить имя владельца сертификата (Subject).');
        end;
        FriendlyNameStr := FriendlyName;

        // Retrieve the certificate thumbprint (SHA-1)
        SetLength(Sha1Thumbprint, 20); // SHA-1 hash is 20 bytes
        Size := Length(Sha1Thumbprint);
        if not CertGetCertificateContextProperty(pCertContext,
            CERT_HASH_PROP_ID,
            @Sha1Thumbprint[0],
            Size) then
          RaiseError('Не удалось получить уникальный отпечаток сертификата (Thumbprint).');

        Result.AddCertOption(FriendlyNameStr, Sha1Thumbprint);
      end;
    except
      CertCloseStore(hStoreHandle, 0);
      raise
    end;
      if not CertCloseStore(hStoreHandle, 0) then
        RaiseError('Не удалось закрыть хранилище сертификатов.');

  end;

end.
