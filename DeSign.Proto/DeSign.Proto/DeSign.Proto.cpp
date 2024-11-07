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

#pragma comment(lib, "Crypt32.lib")

struct CertOption 
{
	std::string friendlyName;
    std::vector<BYTE> thumbprint;
};

static void ThrowError(const std::string& message) {
    DWORD errorCode = GetLastError();
    LPVOID errorMsg = nullptr;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errorMsg,
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

void SignFile(const std::string& filePath, const std::string& thumbprint);

std::vector<BYTE> ReadFileContent(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file.");
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file.");
    }
    return buffer;
}

PCCERT_CONTEXT GetCertificateByThumbprint(const std::string& thumbprint) {
    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!hStore) {
        throw std::runtime_error("Failed to open certificate store.");
    }

    BYTE thumbprintBytes[20];
    DWORD thumbprintSize = sizeof(thumbprintBytes);
    if (!CryptStringToBinaryA(thumbprint.c_str(), thumbprint.length(), CRYPT_STRING_HEX, thumbprintBytes, &thumbprintSize, NULL, NULL)) {
        CertCloseStore(hStore, 0);
        throw std::runtime_error("Failed to convert thumbprint to binary.");
    }

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = thumbprintSize;
    hashBlob.pbData = thumbprintBytes;

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &hashBlob, NULL);
    CertCloseStore(hStore, 0);

    if (!pCertContext) {
        throw std::runtime_error("Certificate not found.");
    } 

    return pCertContext;
}

void SignFile(const std::string& filePath, const std::string& thumbprint) {
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

int PromptUserToSelectCertificate(const std::vector<CertOption>& certificates) {
    size_t choice = 0;
    while (true) {
        std::cout << "Введите номер сертификата для выбора: ";
        std::cin >> choice;

        if (std::cin.fail() || choice < 1 || choice > certificates.size()) {
            std::cin.clear(); // clear the error flag
            std::cout << "Неверный ввод. Пожалуйста, введите номер от 1 до " << certificates.size() << "." << std::endl;
        }
        else {
            return choice; // valid input
        }
    }
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
            const CertOption& selectedCert = res[selectedNumber - 1];
            std::cout << "Вы выбрали сертификат: " << selectedCert.friendlyName << std::endl;
            // Further processing with selectedCert
        }
        else
        {
            std::cout << "Не найдено ни одного сертификата с поддержкой шифрования по алгоритмам ГОСТ" << std::endl;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}


int xxmain() {
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