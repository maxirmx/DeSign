unit Cades;

interface

uses
  Windows,
  SysUtils,
  JwaWinCrypt,
  AdesConstants;

const
  // Signature Types (LOWWORD)
  CADES_DEFAULT       = $00000000;
  CADES_BES           = $00000001;
  CADES_T             = $00000005;
  CADES_X_LONG_TYPE_1 = $0000005D;
  CADES_A             = $000000DD;
  PKCS7_TYPE          = $0000FFFF;

  // Additional Parameters to Signature Type (HIWORD)
  CADES_DISABLE_REDUNDANCY          = ADES_DISABLE_REDUNDANCY;
  CADES_USE_OCSP_AUTHORIZED_POLICY  = ADES_USE_OCSP_AUTHORIZED_POLICY;

  // Authentication Types
  CADES_AUTH_ANONYMOUS = $00;
  CADES_AUTH_BASIC     = $01;
  CADES_AUTH_NTLM      = $02;
  CADES_AUTH_DIGEST    = $08;
  CADES_AUTH_NEGOTIATE = $10;

  // Verification Results
  CADES_VERIFY_SUCCESS                        = ADES_VERIFY_SUCCESS;
  CADES_VERIFY_INVALID_REFS_AND_VALUES        = ADES_VERIFY_INVALID_REFS_AND_VALUES;
  CADES_VERIFY_SIGNER_NOT_FOUND               = ADES_VERIFY_SIGNER_NOT_FOUND;
  CADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP   = ADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP;
  CADES_VERIFY_REFS_AND_VALUES_NO_MATCH       = ADES_VERIFY_REFS_AND_VALUES_NO_MATCH;
  CADES_VERIFY_NO_CHAIN                       = ADES_VERIFY_NO_CHAIN;
  CADES_VERIFY_END_CERT_REVOCATION            = ADES_VERIFY_END_CERT_REVOCATION;
  CADES_VERIFY_CHAIN_CERT_REVOCATION          = ADES_VERIFY_CHAIN_CERT_REVOCATION;
  CADES_VERIFY_BAD_SIGNATURE                  = ADES_VERIFY_BAD_SIGNATURE;
  CADES_VERIFY_NO_VALID_CADES_C_TIMESTAMP     = ADES_VERIFY_NO_VALID_CADES_C_TIMESTAMP;
  CADES_VERIFY_BAD_POLICY                     = ADES_VERIFY_BAD_POLICY;
  CADES_VERIFY_UNSUPPORTED_ATTRIBUTE          = ADES_VERIFY_UNSUPPORTED_ATTRIBUTE;
  CADES_VERIFY_FAILED_POLICY                  = ADES_VERIFY_FAILED_POLICY;
  CADES_VERIFY_ECONTENTTYPE_NO_MATCH          = ADES_VERIFY_ECONTENTTYPE_NO_MATCH;
  CADES_VERIFY_NO_VALID_ARCHIVE_TIMESTAMP     = ADES_VERIFY_NO_VALID_ARCHIVE_TIMESTAMP;

  // Timestamp Parameters
  CADES_TIMESTAMP_NO_CERT_REQ         = ADES_TIMESTAMP_NO_CERT_REQ;
  CADES_CHECK_CERT_REQ                = ADES_CHECK_CERT_REQ;
  CADES_SKIP_IE_PROXY_CONFIGURATION   = ADES_SKIP_IE_PROXY_CONFIGURATION;
  CADES_LEGACY_CRL_RETRIEVE           = ADES_LEGACY_CRL_RETRIEVE;

  // ATS Order
  CADES_ATS_ORDER_BY_DATE_ASC = $00000001;

  // Separator for Additional TSP Service Addresses (CADES-2312)
  CADES_ADDITIONAL_TSA_SEP = '::::';

type
  PPBYTE = ^PBYTE;
  PDWORD = ^DWORD;

  PCADES_AUTH_PARA = ^CADES_AUTH_PARA;
  CADES_AUTH_PARA = record
    dwSize: DWORD;
    dwAuthType: DWORD;
    wszUsername: LPCWSTR;
    wszPassword: LPCWSTR;
    pClientCertificate: PCCERT_CONTEXT;
  end;

  PCADES_SERVICE_CONNECTION_PARA = ^CADES_SERVICE_CONNECTION_PARA;
  CADES_SERVICE_CONNECTION_PARA = record
    dwSize: DWORD;
    wszUri: LPCWSTR;
    pAuthPara: PCADES_AUTH_PARA;
  end;

  PCADES_PROXY_PARA = ^CADES_PROXY_PARA;
  CADES_PROXY_PARA = record
    dwSize: DWORD;
    wszProxyUri: LPCWSTR;
    pProxyAuthPara: PCADES_AUTH_PARA;
  end;

  PCADES_SIGN_PARA = ^CADES_SIGN_PARA;
  CADES_SIGN_PARA = record
    dwSize: DWORD;
    dwCadesType: DWORD;
    pSignerCert: PCCERT_CONTEXT;
    szHashAlgorithm: PAnsiChar;
    hAdditionalStore: HCERTSTORE;
    pTspConnectionPara: PCADES_SERVICE_CONNECTION_PARA;
    pProxyPara: PCADES_PROXY_PARA;
    pCadesExtraPara: Pointer;
  end;

  PCADES_EXTRA_PARA = ^CADES_EXTRA_PARA;
  CADES_EXTRA_PARA = record
    dwSize: DWORD;
    dwFlags: DWORD;
  end;

  PCADES_COSIGN_PARA = ^CADES_COSIGN_PARA;
  CADES_COSIGN_PARA = record
    dwSize: DWORD;
    pSigner: PCMSG_SIGNER_ENCODE_INFO;
    pCadesSignPara: PCADES_SIGN_PARA;
  end;

  PCADES_ENCODE_INFO = ^CADES_ENCODE_INFO;
  CADES_ENCODE_INFO = record
    dwSize: DWORD;
    pSignedEncodeInfo: PCMSG_SIGNED_ENCODE_INFO;
    cSignerCerts: DWORD;
    rgSignerCerts: ^PCERT_CONTEXT;
    cHashAlgorithms: DWORD;
    rgHashAlgorithms: PAnsiChar;
  end;

  PCADES_SIGN_MESSAGE_PARA = ^CADES_SIGN_MESSAGE_PARA;
  CADES_SIGN_MESSAGE_PARA = record
    dwSize: DWORD;
    pSignMessagePara: PCRYPT_SIGN_MESSAGE_PARA;
    pCadesSignPara: PCADES_SIGN_PARA;
  end;

  PCADES_VERIFICATION_PARA = ^CADES_VERIFICATION_PARA;
  CADES_VERIFICATION_PARA = record
    dwSize: DWORD;
    pMessageContentHash: Pointer;
    pProxyPara: PCADES_PROXY_PARA;
    hStore: HCERTSTORE;
    bReserved2: BOOL;
    pReserved3: Pointer;
    dwCadesType: DWORD;
  end;

  PCADES_VERIFICATION_INFO = ^CADES_VERIFICATION_INFO;
  CADES_VERIFICATION_INFO = record
    dwSize: DWORD;
    dwStatus: DWORD;
    pSignerCert: PCCERT_CONTEXT;
    pSigningTime: PFileTime;
    pSignatureTimeStampTime: PFileTime;
  end;

  PCADES_VERIFY_MESSAGE_PARA = ^CADES_VERIFY_MESSAGE_PARA;
  CADES_VERIFY_MESSAGE_PARA = record
    dwSize: DWORD;
    pVerifyMessagePara: PCRYPT_VERIFY_MESSAGE_PARA;
    pCadesVerifyPara: PCADES_VERIFICATION_PARA;
  end;

  CADES_ENHANCE_MESSAGE_PARA = record
    dwSize: Cardinal;
    dwMsgEncodingType: Cardinal;
    pCadesSignPara: PCADES_SIGN_PARA;
  end;
  PCADES_ENHANCE_MESSAGE_PARA = ^CADES_ENHANCE_MESSAGE_PARA;

  CADES_VIEW_SIGNATURE_PARA = record
    dwSize: Cardinal;
    dwMsgEncodingType: Cardinal;
    hCryptProv: Pointer;
  end;
  PCADES_VIEW_SIGNATURE_PARA = ^CADES_VIEW_SIGNATURE_PARA;

  PCADES_CONVERT_CONTEXT = Pointer;

  PPCRYPT_DATA_BLOB = ^PCRYPT_DATA_BLOB;

function CadesMsgOpenToEncode(dwMsgEncodingType: DWORD; dwFlags: DWORD;
  pvMsgEncodeInfo: PCADES_ENCODE_INFO; pszInnerContentObjID: LPSTR;
  pStreamInfo: PCMSG_STREAM_INFO): HCRYPTMSG; stdcall; external 'CADES.dll';

function CadesMsgIsType(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  dwCadesType: DWORD; out pbResult: BOOL): BOOL; stdcall; external 'CADES.dll';

function CadesMsgIsTypeEncoded(dwEncodingType: DWORD; pbSignerInfo: PBYTE;
  cbSignerInfo: DWORD; dwCadesType: DWORD; out pbResult: BOOL): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgEnhanceSignature(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  pCadesSignPara: PCADES_SIGN_PARA): BOOL; stdcall; external 'CADES.dll';

function CadesMsgEnhanceSignatureAll(hCryptMsg: HCRYPTMSG;
  pCadesSignPara: PCADES_SIGN_PARA): BOOL; stdcall; external 'CADES.dll';

function CadesMsgAddEnhancedSignature(hCryptMsg: HCRYPTMSG;
  pCadesCosignPara: PCADES_COSIGN_PARA): BOOL; stdcall; external 'CADES.dll';

function CadesMsgVerifySignature(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  pVerificationPara: PCADES_VERIFICATION_PARA; out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgCountersignEncoded(dwEncodingType: DWORD; pbSignerInfo: PBYTE;
  cbSignerInfo: DWORD; cCountersigners: DWORD; rgCountersigners: PCADES_COSIGN_PARA;
  out ppCountersignature: PCRYPT_DATA_BLOB): BOOL; stdcall; external 'CADES.dll';

function CadesMsgCountersign(hCryptMsg: HCRYPTMSG; dwIndex: DWORD; cCountersigners: DWORD;
  rgCountersigners: PCADES_COSIGN_PARA): BOOL; stdcall; external 'CADES.dll';

function CadesMsgVerifyCountersignatureEncoded(hCryptProv: HCRYPTPROV; dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; pbSignerInfoCountersignature: PBYTE;
  cbSignerInfoCountersignature: DWORD; pciCountersigner: PCERT_INFO; 
  pVerificationPara: PCADES_VERIFICATION_PARA; out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgVerifyCountersignatureEncodedEx(hCryptProv: HCRYPTPROV; dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; pbSignerInfoCountersignature: PBYTE;
  cbSignerInfoCountersignature: DWORD; dwSignerType: DWORD; pvSigner: Pointer;
  dwFlags: DWORD; pvReserved: Pointer; pVerificationPara: PCADES_VERIFICATION_PARA;
  out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetSigningCertId(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out ppCertId: PCRYPT_DATA_BLOB): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetSigningCertIdEx(pSignerInfo: PCMSG_SIGNER_INFO;
  out ppCertId: PCRYPT_DATA_BLOB): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetSigningCertIdEncoded(dwEncodingType: DWORD; pbSignerInfo: PBYTE;
  cbSignerInfo: DWORD; out ppCertId: PCRYPT_DATA_BLOB): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetSigningCertIdHashAlg(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD): ALG_ID; stdcall;
  external 'CADES.dll';

function CadesMsgGetSignatureTimestamps(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetCadesCTimestamps(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetArchiveTimestamps(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD; 
  dwFlags: DWORD; pvReserved: Pointer; out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetCertificateValues(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out ppCertificates: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetRevocationValues(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out ppCRLs: PCADES_BLOB_ARRAY; out ppBasicOCSPResponses: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetSigningCertIdHashAlgEx(pSignerInfo: PCMSG_SIGNER_INFO): ALG_ID; stdcall;
  external 'CADES.dll';

function CadesMsgGetSignatureTimestampsEx(pSignerInfo: PCMSG_SIGNER_INFO;
  out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetCadesCTimestampsEx(pSignerInfo: PCMSG_SIGNER_INFO;
  out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetArchiveTimestampsEx(pSignerInfo: PCMSG_SIGNER_INFO; dwFlags: DWORD;
  pvReserved: Pointer; out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetCertificateValuesEx(pSignerInfo: PCMSG_SIGNER_INFO;
  out ppCertificates: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetRevocationValuesEx(pSignerInfo: PCMSG_SIGNER_INFO;
  out ppCRLs: PCADES_BLOB_ARRAY; out ppBasicOCSPResponses: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetSignatureTimestampsEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';
function CadesMsgGetCadesCTimestampsEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetArchiveTimestampsEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; dwFlags: DWORD; pvReserved: Pointer;
  out ppTimestamps: PCADES_BLOB_ARRAY): BOOL; stdcall; external 'CADES.dll';

function CadesMsgGetCertificateValuesEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; out ppCertificates: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetRevocationValuesEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD; out ppCRLs: PCADES_BLOB_ARRAY;
  out ppBasicOCSPResponses: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgGetSigningCertIdHashAlgEncoded(dwEncodingType: DWORD;
  pbSignerInfo: PBYTE; cbSignerInfo: DWORD): ALG_ID; stdcall;
  external 'CADES.dll';

function CadesMsgUIDisplaySignature(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  hwndParent: HWND; title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgUIDisplaySignatureByHash(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  hwndParent: HWND; title: LPCWSTR; pbHashBlob: PBYTE; cbHashBlob: DWORD;
  pHashAlgorithm: PCRYPT_ALGORITHM_IDENTIFIER): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgUIDisplaySignatures(hCryptMsg: HCRYPTMSG; hwndParent: HWND;
  title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgUIDisplaySignaturesByHash(hCryptMsg: HCRYPTMSG; hwndParent: HWND;
  title: LPCWSTR; pbHashBlob: PBYTE; cbHashBlob: DWORD;
  pHashAlgorithm: PCRYPT_ALGORITHM_IDENTIFIER): BOOL; stdcall; external 'CADES.dll';

function CadesMsgViewSignature(hCryptMsg: HCRYPTMSG; dwSignatureIndex: DWORD;
  out prgPropPages: Pointer; out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesMsgViewSignatures(hCryptMsg: HCRYPTMSG; out prgPropPages: Pointer;
  out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesViewSignature(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  dwSignatureIndex: DWORD; pbSignedBlob: PBYTE; cbSignedBlob: DWORD;
  out prgPropPages: Pointer; out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesViewSignatureDetached(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  dwSignatureIndex: DWORD; pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD;
  cToBeSigned: DWORD; rgpbToBeSigned: PBYTE; rgcbToBeSigned: DWORD;
  out prgPropPages: Pointer; out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesViewSignatures(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  pbSignedBlob: PBYTE; cbSignedBlob: DWORD; out prgPropPages: Pointer;
  out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesViewSignaturesDetached(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD; cToBeSigned: DWORD;
  rgpbToBeSigned: PBYTE; rgcbToBeSigned: DWORD; out prgPropPages: Pointer;
  out pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesUIDisplaySignature(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  dwSignatureIndex: DWORD; pbSignedBlob: PBYTE; cbSignedBlob: DWORD;
  hwndParent: HWND; title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesUIDisplaySignatures(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  pbSignedBlob: PBYTE; cbSignedBlob: DWORD; hwndParent: HWND; title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesUIDisplaySignatureDetached(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  dwSignatureIndex: DWORD; pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD;
  cToBeSigned: DWORD; rgpbToBeSigned: PBYTE; rgcbToBeSigned: DWORD;
  hwndParent: HWND; title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesUIDisplaySignaturesDetached(pCadesViewSignaturePara: PCADES_VIEW_SIGNATURE_PARA;
  pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD; cToBeSigned: DWORD;
  rgpbToBeSigned: PBYTE; rgcbToBeSigned: DWORD; hwndParent: HWND; title: LPCWSTR): BOOL; stdcall;
  external 'CADES.dll';

function CadesFreeSignaturePropPages(prgPropPages: Pointer;
  pcPropPages: DWORD): BOOL; stdcall;
  external 'CADES.dll';

function CadesSignMessage(pSignPara: PCADES_SIGN_MESSAGE_PARA; fDetachedSignature: BOOL;
  cToBeSigned: DWORD; rgpbToBeSigned: Pointer; rgcbToBeSigned: PDWORD;
  ppSignedBlob: PPCRYPT_DATA_BLOB): BOOL; stdcall; external 'CADES.dll';

function CadesSignHash(pSignPara: PCADES_SIGN_MESSAGE_PARA; pbHash: PBYTE;
  cbHash: DWORD; pszInnerContentObjID: LPCSTR; out ppSignedBlob: PCRYPT_DATA_BLOB): BOOL; stdcall;
  external 'CADES.dll';

function CadesVerifyHash(pVerifyPara: PCADES_VERIFY_MESSAGE_PARA; dwSignerIndex: DWORD;
  pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD; pbHash: PBYTE; cbHash: DWORD;
  pHashAlgorithm: PCRYPT_ALGORITHM_IDENTIFIER; out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesAddHashSignature(pSignPara: PCADES_SIGN_MESSAGE_PARA;
  pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD; pbHash: PBYTE;
  cbHash: DWORD; out ppSignedBlob: PCRYPT_DATA_BLOB): BOOL; stdcall;
  external 'CADES.dll';

function CadesVerifyMessage(pVerifyPara: PCADES_VERIFY_MESSAGE_PARA; dwSignerIndex: DWORD;
  pbSignedBlob: PBYTE; cbSignedBlob: DWORD; out ppDecodedBlob: PCRYPT_DATA_BLOB;
  out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesVerifyDetachedMessage(pVerifyPara: PCADES_VERIFY_MESSAGE_PARA;
  dwSignerIndex: DWORD; pbDetachedSignBlob: PBYTE; cbDetachedSignBlob: DWORD;
  cToBeSigned: DWORD; rgpbToBeSigned: PBYTE; rgcbToBeSigned: DWORD;
  out ppVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesEnhanceMessage(pEnhancePara: PCADES_ENHANCE_MESSAGE_PARA; dwSignerIndex: DWORD;
  pbSignedBlob: PBYTE; cbSignedBlob: DWORD; out ppEnhancedBlob: PCRYPT_DATA_BLOB): BOOL; stdcall;
  external 'CADES.dll';

function CadesEnhanceMessageAll(pEnhancePara: PCADES_ENHANCE_MESSAGE_PARA;
  pbSignedBlob: PBYTE; cbSignedBlob: DWORD; out ppEnhancedBlob: PCRYPT_DATA_BLOB): BOOL; stdcall;
  external 'CADES.dll';

function CadesFreeVerificationInfo(pVerificationInfo: PCADES_VERIFICATION_INFO): BOOL; stdcall;
  external 'CADES.dll';

function CadesFreeBlob(pBlob: PCRYPT_DATA_BLOB): BOOL; stdcall;
  external 'CADES.dll';

function CadesFreeBlobArray(pBlobArray: PCADES_BLOB_ARRAY): BOOL; stdcall;
  external 'CADES.dll';

function CadesFormatMessage(dwFlags: DWORD; lpSource: Pointer; dwMessageId: DWORD;
  dwLanguageId: DWORD; lpBuffer: PWideChar; nSize: DWORD; Arguments: va_list): DWORD; stdcall;
  external 'CADES.dll';


function CadesMsgConvertCreateContext(pStreamInfo: PCMSG_STREAM_INFO; pbDetachedMessage: PBYTE;
  cbDetachedMessage: DWORD): PCADES_CONVERT_CONTEXT; stdcall;
  external 'CADES.dll';

function CadesMsgConvertUpdate(pConvertContext: PCADES_CONVERT_CONTEXT; pbData: PBYTE;
  cbData: DWORD; fFinal: BOOL): BOOL; stdcall; external 'CADES.dll';

function CadesMsgConvertFreeContext(pConvertContext: PCADES_CONVERT_CONTEXT): BOOL; stdcall;
  external 'CADES.dll';


implementation

end.

