unit GostOIDs;

interface

const
  // CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID
  CP_GOST_PRIVATE_KEYS_V1 = '1.2.643.2.2.37.1';
  CP_GOST_PRIVATE_KEYS_V2 = '1.2.643.2.2.37.2';
  CP_GOST_PRIVATE_KEYS_V2_FULL = '1.2.643.2.2.37.2.1';
  CP_GOST_PRIVATE_KEYS_V2_PARTOF = '1.2.643.2.2.37.2.2';

  // CRYPT_HASH_ALG_OID_GROUP_ID
  CP_GOST_R3411 = '1.2.643.2.2.9';
  CP_GOST_R3411_12_256 = '1.2.643.7.1.1.2.2';
  CP_GOST_R3411_12_512 = '1.2.643.7.1.1.2.3';

  // CRYPT_ENCRYPT_ALG_OID_GROUP_ID
  CP_GOST_28147 = '1.2.643.2.2.21';
  CP_GOST_R3412_2015_M = '1.2.643.7.1.1.5.1';
  CP_GOST_R3412_2015_K = '1.2.643.7.1.1.5.2';
  CP_GOST_R3412_2015_M_CTR_ACPKM = '1.2.643.7.1.1.5.1.1';
  CP_GOST_R3412_2015_M_CTR_ACPKM_OMAC = '1.2.643.7.1.1.5.1.2';
  CP_GOST_R3412_2015_K_CTR_ACPKM = '1.2.643.7.1.1.5.2.1';
  CP_GOST_R3412_2015_K_CTR_ACPKM_OMAC = '1.2.643.7.1.1.5.2.2';

  CP_GOST_R3412_2015_M_KEXP15 = '1.2.643.7.1.1.7.1.1';
  CP_GOST_R3412_2015_K_KEXP15 = '1.2.643.7.1.1.7.2.1';

  // CRYPT_PUBKEY_ALG_OID_GROUP_ID
  CP_GOST_R3410 = '1.2.643.2.2.20';
  CP_GOST_R3410EL = '1.2.643.2.2.19';
  CP_GOST_R3410_12_256 = '1.2.643.7.1.1.1.1';
  CP_GOST_R3410_12_512 = '1.2.643.7.1.1.1.2';
  CP_DH_EX = '1.2.643.2.2.99';
  CP_DH_EL = '1.2.643.2.2.98';
  CP_DH_12_256 = '1.2.643.7.1.1.6.1';
  CP_DH_12_512 = '1.2.643.7.1.1.6.2';
  CP_GOST_R3410_94_ESDH = '1.2.643.2.2.97';
  CP_GOST_R3410_01_ESDH = '1.2.643.2.2.96';

  // CRYPT_SIGN_ALG_OID_GROUP_ID
  CP_GOST_R3411_R3410 = '1.2.643.2.2.4';
  CP_GOST_R3411_R3410EL = '1.2.643.2.2.3';
  CP_GOST_R3411_12_256_R3410 = '1.2.643.7.1.1.3.2';
  CP_GOST_R3411_12_512_R3410 = '1.2.643.7.1.1.3.3';

  // CRYPT_ENHKEY_USAGE_OID_GROUP_ID
  KP_TLS_PROXY = '1.2.643.2.2.34.1';
  KP_RA_CLIENT_AUTH = '1.2.643.2.2.34.2';
  KP_WEB_CONTENT_SIGNING = '1.2.643.2.2.34.3';
  KP_RA_ADMINISTRATOR = '1.2.643.2.2.34.4';
  KP_RA_OPERATOR = '1.2.643.2.2.34.5';

  // HMAC algorithms
  CP_GOST_R3411_94_HMAC = '1.2.643.2.2.10';
  CP_GOST_R3411_2012_256_HMAC = '1.2.643.7.1.1.4.1';
  CP_GOST_R3411_2012_512_HMAC = '1.2.643.7.1.1.4.2';

  // Qualified Certificate
  OGRN = '1.2.643.100.1';
  OGRNIP = '1.2.643.100.5';
  SNILS = '1.2.643.100.3';
  INNLE = '1.2.643.100.4';
  INN = '1.2.643.3.131.1.1';

  // Signature tool class
  SIGN_TOOL_KC1 = '1.2.643.100.113.1';
  SIGN_TOOL_KC2 = '1.2.643.100.113.2';
  SIGN_TOOL_KC3 = '1.2.643.100.113.3';
  SIGN_TOOL_KB1 = '1.2.643.100.113.4';
  SIGN_TOOL_KB2 = '1.2.643.100.113.5';
  SIGN_TOOL_KA1 = '1.2.643.100.113.6';

  // CA tool class
  CA_TOOL_KC1 = '1.2.643.100.114.1';
  CA_TOOL_KC2 = '1.2.643.100.114.2';
  CA_TOOL_KC3 = '1.2.643.100.114.3';
  CA_TOOL_KB1 = '1.2.643.100.114.4';
  CA_TOOL_KB2 = '1.2.643.100.114.5';
  CA_TOOL_KA1 = '1.2.643.100.114.6';

  // Our well-known policy ID
  CEP_BASE_PERSONAL = '1.2.643.2.2.38.1';
  CEP_BASE_NETWORK = '1.2.643.2.2.38.2';

  // OIDs for HASH
  GostR3411_94_TestParamSet = '1.2.643.2.2.30.0';
  GostR3411_94_CryptoProParamSet = '1.2.643.2.2.30.1';
  GostR3411_94_CryptoPro_B_ParamSet = '1.2.643.2.2.30.2';
  GostR3411_94_CryptoPro_C_ParamSet = '1.2.643.2.2.30.3';
  GostR3411_94_CryptoPro_D_ParamSet = '1.2.643.2.2.30.4';

  // OIDs for Crypt
  Gost28147_89_TestParamSet = '1.2.643.2.2.31.0';
  Gost28147_89_CryptoPro_A_ParamSet = '1.2.643.2.2.31.1';
  Gost28147_89_CryptoPro_B_ParamSet = '1.2.643.2.2.31.2';
  Gost28147_89_CryptoPro_C_ParamSet = '1.2.643.2.2.31.3';
  Gost28147_89_CryptoPro_D_ParamSet = '1.2.643.2.2.31.4';
  Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = '1.2.643.2.2.31.5';
  Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = '1.2.643.2.2.31.6';
  Gost28147_89_CryptoPro_RIC_1_ParamSet = '1.2.643.2.2.31.7';

  Gost28147_89_TC26_A_ParamSet = '1.2.643.2.2.31.12';
  Gost28147_89_TC26_B_ParamSet = '1.2.643.2.2.31.13';
  Gost28147_89_TC26_C_ParamSet = '1.2.643.2.2.31.14';
  Gost28147_89_TC26_D_ParamSet = '1.2.643.2.2.31.15';
  Gost28147_89_TC26_E_ParamSet = '1.2.643.2.2.31.16';
  Gost28147_89_TC26_F_ParamSet = '1.2.643.2.2.31.17';

// OID for Gost28147-89 TC26 Z ParamSet
  CP_GOST_28147_89_TC26_Z_ParamSet = '1.2.643.7.1.2.5.1.1';  // ГОСТ 28147-89, параметры шифрования ТС26 Z

  // OID for Signature 1024
  CP_GOST_R3410_94_CryptoPro_A_ParamSet = '1.2.643.2.2.32.2';  // VerbaO
  CP_GOST_R3410_94_CryptoPro_B_ParamSet = '1.2.643.2.2.32.3';
  CP_GOST_R3410_94_CryptoPro_C_ParamSet = '1.2.643.2.2.32.4';
  CP_GOST_R3410_94_CryptoPro_D_ParamSet = '1.2.643.2.2.32.5';

  // OID for Signature 512
  CP_GOST_R3410_94_TestParamSet = '1.2.643.2.2.32.0';  // Test

  // OID for DH 1024
  CP_GOST_R3410_94_CryptoPro_XchA_ParamSet = '1.2.643.2.2.33.1';
  CP_GOST_R3410_94_CryptoPro_XchB_ParamSet = '1.2.643.2.2.33.2';
  CP_GOST_R3410_94_CryptoPro_XchC_ParamSet = '1.2.643.2.2.33.3';

  // OID for EC signature
  CP_GOST_R3410_2001_TestParamSet = '1.2.643.2.2.35.0';  // ГОСТ Р 34.10 256 бит, тестовые параметры
  CP_GOST_R3410_2001_CryptoPro_A_ParamSet = '1.2.643.2.2.35.1';  // ГОСТ Р 34.10 256 бит, параметры по умолчанию
  CP_GOST_R3410_2001_CryptoPro_B_ParamSet = '1.2.643.2.2.35.2';  // ГОСТ Р 34.10 256 бит, параметры Оскар 2.x
  CP_GOST_R3410_2001_CryptoPro_C_ParamSet = '1.2.643.2.2.35.3';  // ГОСТ Р 34.10 256 бит, параметры подписи 1

  // OID for TC26 GOST 3410 12 256 ParamSet
  CP_TC26_GOST_3410_12_256_ParamSetA = '1.2.643.7.1.2.1.1.1';  // ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор A
  CP_TC26_GOST_3410_12_256_ParamSetB = '1.2.643.7.1.2.1.1.2';  // ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор B
  CP_TC26_GOST_3410_12_256_ParamSetC = '1.2.643.7.1.2.1.1.3';  // ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор C
  CP_TC26_GOST_3410_12_256_ParamSetD = '1.2.643.7.1.2.1.1.4';  // ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор D

  // OID for TC26 GOST 3410 12 512 ParamSet
  CP_TC26_GOST_3410_12_512_ParamSetTest = '1.2.643.7.1.2.1.2.0';  // ГОСТ Р 34.10-2012, 512 бит, тестовые параметры
  CP_TC26_GOST_3410_12_512_ParamSetA = '1.2.643.7.1.2.1.2.1';  // ГОСТ Р 34.10-2012, 512 бит, параметры по умолчанию
  CP_TC26_GOST_3410_12_512_ParamSetB = '1.2.643.7.1.2.1.2.2';  // ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор B
  CP_TC26_GOST_3410_12_512_ParamSetC = '1.2.643.7.1.2.1.2.3';  // ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор С

  // OID for EC DH
  CP_GOST_R3410_2001_CryptoPro_XchA_ParamSet = '1.2.643.2.2.36.0';  // ГОСТ Р 34.10 256 бит, параметры обмена по умолчанию
  CP_GOST_R3410_2001_CryptoPro_XchB_ParamSet = '1.2.643.2.2.36.1';  // ГОСТ Р 34.10 256 бит, параметры обмена 1

  // OIDs for private key container extensions
  CP_CryptoPro_Private_Keys_Extension_Intermediate_Store = '1.2.643.2.2.37.3.1';
  CP_CryptoPro_Private_Keys_Extension_Signature_Trust_Store = '1.2.643.2.2.37.3.2';
  CP_CryptoPro_Private_Keys_Extension_Exchange_Trust_Store = '1.2.643.2.2.37.3.3';
  CP_CryptoPro_Private_Keys_Extension_Container_Friendly_Name = '1.2.643.2.2.37.3.4';
  CP_CryptoPro_Private_Keys_Extension_Container_Key_Usage_Period = '1.2.643.2.2.37.3.5';
  CP_CryptoPro_Private_Keys_Extension_Container_UEC_Symmetric_Key_Derive_Counter = '1.2.643.2.2.37.3.6';

  CP_CryptoPro_Private_Keys_Extension_Container_Primary_Key_Properties = '1.2.643.2.2.37.3.7';
  CP_CryptoPro_Private_Keys_Extension_Container_Secondary_Key_Properties = '1.2.643.2.2.37.3.8';

  CP_CryptoPro_Private_Keys_Extension_Container_Signature_Key_Usage_Period = '1.2.643.2.2.37.3.9';
  CP_CryptoPro_Private_Keys_Extension_Container_Exchange_Key_Usage_Period = '1.2.643.2.2.37.3.10';
  CP_CryptoPro_Private_Keys_Extension_Container_Key_Time_Validity_Control_Mode = '1.2.643.2.2.37.3.11';

  CP_CryptoPro_Private_Keys_Extension_Container_ARandom_State = '1.2.643.2.2.37.3.13';
  CP_CryptoPro_Private_Keys_Extension_Container_Shared_Container = '1.2.643.2.2.37.3.14';

  CP_CryptoPro_Private_Keys_Extension_License = '1.2.643.2.2.37.3.15';

  CP_CryptoPro_Private_Keys_Extension_Container_String_Config = '1.2.643.2.2.37.3.17';

  // OIDs for certificate and CRL extensions
  CP_CryptoPro_Extensions_Certificate_and_CRL_Matching_Technique = '1.2.643.2.2.49.1';
  CP_CPOID_SubjectSignTool = '1.2.643.100.111';  // Средство электронной подписи владельца
  CP_CPOID_IssuerSignTool = '1.2.643.100.112';  // Средства электронной подписи и УЦ издателя
  CP_OID_IdentificationKind = '1.2.643.100.114';  // Тип идентификации при выдаче сертификата

  // OID for CMS 2015 MAC attribute
  CP_CPOID_CMS_GR3412_OMAC = '1.2.643.7.1.0.6.1.1';

implementation

end.


implementation

end.

