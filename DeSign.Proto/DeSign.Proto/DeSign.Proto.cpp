/// DeCades.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <limits>

#include "cades.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Cades.lib")

struct CertOption 
{
	std::string friendlyName;
    std::vector<BYTE> thumbprint;
};

static void ThrowError(const std::string& message) {
    DWORD errorCode = GetLastError();
    LPVOID errorMsg = nullptr;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&errorMsg,
        0,
        NULL
    );
    std::string error = message + " [" + std::to_string(errorCode) + "] " + (char*)errorMsg;
    LocalFree(errorMsg);
	throw std::runtime_error(error);
}

static std::vector<CertOption> GetCertificates(const std::string& prefix) {

    std::vector<CertOption> res;
    // Open the "MY" certificate store.
    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));
    if (!hStoreHandle) {
        ThrowError("Не удалось открыть хранилище сертификатов.");
    }

    try {

        // Enumerate the certificates in the store.
        PCCERT_CONTEXT pCertContext = NULL;
        while (pCertContext = CertEnumCertificatesInStore(hStoreHandle, pCertContext)) {
            // Check if the certificate's signature algorithm matches the filter.
            std::string algorithmId(pCertContext->pCertInfo->SignatureAlgorithm.pszObjId);
            if (algorithmId.find(prefix) != 0) continue; // Skip this certificate if it doesn't match the filter.

            // Get the friendly name of the certificate.
            char friendlyName[256];
            if (!CertGetNameStringA(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, friendlyName, sizeof(friendlyName)) || friendlyName[0] == '\0') {
                // If friendly name is empty, use the subject name.
                if (!CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, friendlyName, sizeof(friendlyName))) {
                    ThrowError("Не удалось открыть получить 'Subject' для сертификата.");
                    return res;
                }
            }

            // Retrieve and print the certificate thumbprint (SHA-1).
            BYTE sha1Thumbprint[20]; // SHA-1 hash is 20 bytes
            DWORD size = sizeof(sha1Thumbprint);
            if (!CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, sha1Thumbprint, &size)) {
                ThrowError("Не удалось получить 'Thumbprint' для сертификата.");
                return res;
            }
            res.push_back({ friendlyName, std::vector<BYTE>(sha1Thumbprint, sha1Thumbprint + sizeof(sha1Thumbprint)) });
        }
    }
	catch (const std::exception& e) 
    {
		CertCloseStore(hStoreHandle, 0);
		throw e;
	}
    // Close the certificate store.
    if (!CertCloseStore(hStoreHandle, 0)) {
        ThrowError("Не удалось закрыть хранилище сертификатов.");
    }

    return res;
}

static const char* GetHashOid(PCCERT_CONTEXT pCert) {
    const char* pKeyAlg = pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(pKeyAlg, szOID_CP_GOST_R3410EL) == 0)
    {
        return szOID_CP_GOST_R3411;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_256) == 0)
    {
        return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_512) == 0)
    {
        return szOID_CP_GOST_R3411_12_512;
    }
    return NULL;
}


static std::string GetUniqueSignatureFileName(const std::string& fileName) {
    size_t lastDot = fileName.find_last_of(".");
    std::string baseName = (lastDot == std::string::npos) ? fileName : fileName.substr(0, lastDot);
    std::string extension = ".sig";
    std::string newFileName = baseName + extension;
    int counter = 1;

    // Check if file exists
    auto fileExists = [](const std::string& name) {
        std::ifstream f(name.c_str());
        return f.good();
        };

    while (fileExists(newFileName)) {
        newFileName = baseName + extension + std::to_string(counter);
        ++counter;
    }

    return newFileName;
}

static std::vector<BYTE> ReadFileContent(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        ThrowError("Failed to open file '" + filePath + "'");
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        ThrowError("Failed to read file '" + filePath + "'");
    }
    return buffer;
}

static void SaveVectorToFile(const std::string& fileName, const std::vector<BYTE>& data) {
    // Check if file already exists
    std::ifstream infile(fileName);
    if (infile.good()) {
        ThrowError("File already exists: " + fileName);
    }

    // Write data to file
    std::ofstream outfile(fileName, std::ios::binary);
    if (!outfile) {
        ThrowError("Failed to open file for writing: " + fileName);
    }

    outfile.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!outfile) {
        ThrowError("Failed to write data to file: " + fileName);
    }
}

static PCCERT_CONTEXT GetCertificateByThumbprint(HCERTSTORE hStore, const std::vector<BYTE>& thumbprint) {
    PCCERT_CONTEXT pCertContext = nullptr;

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = thumbprint.size();
    hashBlob.pbData = const_cast<BYTE*>(thumbprint.data());

    pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &hashBlob, NULL);
	if (!pCertContext) {
		ThrowError("Failed to find certificate by thumbprint.");
	}
    return pCertContext;
}

static void SignFile(const std::string& filePath, const std::vector<BYTE>& thumbprint) {
    HCERTSTORE hStore = nullptr;
	PCCERT_CONTEXT pCertContext = nullptr;
    PCRYPT_DATA_BLOB pSignedMessage = nullptr;
    PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

    try {
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
        if (!hStore) {
            ThrowError("Failed to open certificate store.");
        }

        pCertContext = GetCertificateByThumbprint(hStore, thumbprint);
        std::string signatureFileName = GetUniqueSignatureFileName(filePath);
        std::vector<BYTE> fileContent = ReadFileContent(filePath);

        // Задаем параметры 
        CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
        signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        signPara.pSigningCert = pCertContext;
        signPara.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(pCertContext);

        CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
        cadesSignPara.dwCadesType = CADES_BES;

        CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
        para.pSignMessagePara = &signPara;
        para.pCadesSignPara = &cadesSignPara;

        // Формируем данные для подписания
        const unsigned char* pbToBeSigned[] = { &fileContent[0] };
        DWORD cbToBeSigned[] = { (DWORD)fileContent.size() };

        CERT_CHAIN_PARA		ChainPara = { sizeof(ChainPara) };

        std::vector<PCCERT_CONTEXT> certs;

        if (CertGetCertificateChain(
            NULL,
            pCertContext,
            NULL,
            NULL,
            &ChainPara,
            0,
            NULL,
            &pChainContext)) {

            for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement - 1; ++i)
            {
                certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
            }
        }
        // Добавляем в сообщение цепочку сертификатов без корневого
        if (certs.size() > 0)
        {
            signPara.cMsgCert = (DWORD)certs.size();
            signPara.rgpMsgCert = &certs[0];
        }


        // Создаем подписанное сообщение
        if (!CadesSignMessage(&para, 0, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
            std::cout << "CadesSignMessage() failed" << std::endl;
        }

        std::vector<unsigned char> message(pSignedMessage->cbData);
        std::copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

        SaveVectorToFile(signatureFileName, message);

        std::cout << "Signature was saved successfully" << std::endl;


        if (pChainContext != nullptr)
        {
            CertFreeCertificateChain(pChainContext);
            pChainContext = nullptr;
        }

        if (pSignedMessage != nullptr) {
            CadesFreeBlob(pSignedMessage);
			pSignedMessage = nullptr;
        }

        if (pCertContext != nullptr)
        {
            CertFreeCertificateContext(pCertContext);
			pCertContext = nullptr;
        }

        if (hStore != nullptr)
        {
            CertCloseStore(hStore, 0);
            hStore = nullptr;
        }
    }
	catch (const std::exception& e) {
        if (pChainContext != nullptr)
            CertFreeCertificateChain(pChainContext);
		if (pSignedMessage)
			CadesFreeBlob(pSignedMessage);
        if (pCertContext)
            CertFreeCertificateContext(pCertContext);
        if (hStore)
            CertCloseStore(hStore, 0);
        throw e;
	}
}



/*void SignFile(const std::string& filePath, const std::string& thumbprint) {
    PCCERT_CONTEXT pCertContext = GetCertificateByThumbprint(thumbprint);
    if (!pCertContext) {
        throw std::runtime_error("Certificate not found.");
    }

    std::vector<BYTE> fileContent = ReadFileContent(filePath);

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
    DWORD dwKeySpec = 0;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;
    if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey)) {
        CertFreeCertificateContext(pCertContext);
        throw std::runtime_error("Failed to acquire private key.");
    }

    HCRYPTHASH hHash = NULL;
    if (!CryptCreateHash(hCryptProvOrNCryptKey, CALG_SHA_256, 0, 0, &hHash)) {
        if (fCallerFreeProvOrNCryptKey) {
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        }
        CertFreeCertificateContext(pCertContext);
        throw std::runtime_error("Failed to create hash.");
    }

    if (!CryptHashData(hHash, fileContent.data(), fileContent.size(), 0)) {
        CryptDestroyHash(hHash);
        if (fCallerFreeProvOrNCryptKey) {
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        }
        CertFreeCertificateContext(pCertContext);
        throw std::runtime_error("Failed to hash data.");
    }

    DWORD dwSigLen = 0;
    if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &dwSigLen)) {
        CryptDestroyHash(hHash);
        if (fCallerFreeProvOrNCryptKey) {
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        }
        CertFreeCertificateContext(pCertContext);
        throw std::runtime_error("Failed to get signature length.");
    }

    std::vector<BYTE> signature(dwSigLen);
    if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, signature.data(), &dwSigLen)) {
        CryptDestroyHash(hHash);
        if (fCallerFreeProvOrNCryptKey) {
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        }
        CertFreeCertificateContext(pCertContext);
        throw std::runtime_error("Failed to sign hash.");
    }

    CryptDestroyHash(hHash);
    if (fCallerFreeProvOrNCryptKey) {
        CryptReleaseContext(hCryptProvOrNCryptKey, 0);
    }
    CertFreeCertificateContext(pCertContext);

    std::ofstream signatureFile(filePath + ".sig", std::ios::binary);
    if (!signatureFile) {
        throw std::runtime_error("Failed to open signature file.");
    }
    signatureFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());
}
*/

static std::ostream& PrintHex(std::ostream& s, const BYTE* data, DWORD size) {
    for (DWORD i = 0; i < size; ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s << std::dec;
}

static void PrintTableHeader() {
    std::cout << std::left << std::setw(5) << "No."
        << std::setw(30) << " Friendly Name"
        << " Thumbprint" << std::endl;
    std::cout << std::string(5, '-') << " "
        << std::string(30, '-') << " "
        << std::string(40, '-') << std::endl;
}

// Function to print the table row
static void PrintTableRow(size_t index, const CertOption& cert) {
    std::cout << std::left << std::setw(5) << std::setfill(' ') << index + 1 << " "
        << std::setw(30) << std::setfill(' ') << cert.friendlyName << " ";
    PrintHex(std::cout, cert.thumbprint.data(), cert.thumbprint.size()) << std::endl;
}

static int PromptUserToSelectCertificate(const std::vector<CertOption>& certificates) {
    size_t choice = 0;
    while (true) {
        std::cout << "Введите номер сертификата для выбора и нажмите <ENTER> ";

        std::string input;
        std::getline(std::cin, input);
        try {
            choice = std::stoul(input);
        } catch (const std::invalid_argument&) {
            std::cout << "Неверный ввод. Пожалуйста, введите номер от 1 до " << certificates.size() << "." << std::endl;
            continue;
        } catch (const std::out_of_range&) {
            std::cout << "Неверный ввод. Пожалуйста, введите номер от 1 до " << certificates.size() << "." << std::endl;
            continue;
        }

        if (choice < 1 || choice > certificates.size()) {
            std::cout << "Неверный ввод. Пожалуйста, введите номер от 1 до " << certificates.size() << "." << std::endl;
        } else {
            return choice; // valid input
        }
    }
}

static std::string PromptUserToEnterFileName() {
    std::string fileName;
    std::cout << "Введите имя файла, который необходимо подписать и нажмите <ENTER> ";
    std::getline(std::cin, fileName);
    return fileName;
}

int main()
{
    try
    {
        auto res = GetCertificates("1.2.643"); // Стандарт.ИСО.Россия = ГОСТ

        if (!res.empty())
        {
            std::cout << "Сертификаты, которые поддерживают шифрование по алгоритмам ГОСТ" << std::endl;
            PrintTableHeader();
            for (size_t i = 0; i < res.size(); ++i) {
                PrintTableRow(i, res[i]);
            }

            // Prompt user to select an item by its number
            int selectedNumber = PromptUserToSelectCertificate(res);
            const CertOption& selectedCert = res[static_cast<std::vector<CertOption, std::allocator<CertOption>>::size_type>(selectedNumber) - 1];
            std::cout << "Вы выбрали сертификат: " << selectedCert.friendlyName << std::endl;
            
			std::string fileName = PromptUserToEnterFileName();
			SignFile(fileName, selectedCert.thumbprint);
        }
        else
        {
            std::cout << "Не найдено ни одного сертификата с поддержкой шифрования по алгоритмам ГОСТ" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }

    std::cout << "Press ENTER to exit...";
    std::string input;
    std::getline(std::cin, input); 
    return 0;
}


/*int xxmain() {
    try {
        std::string filePath = "path_to_your_file";
        std::string thumbprint = "your_certificate_thumbprint";
        SignFile(filePath, thumbprint);
        std::cout << "File signed successfully." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
*/