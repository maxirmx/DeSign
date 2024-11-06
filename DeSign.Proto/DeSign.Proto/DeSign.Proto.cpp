/// DeCades.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

struct CertOption 
{
	std::string friendlyName;
    std::vector<BYTE> thumbprint;
};

struct CertOptions
{
	std::vector<CertOption> certs;
    std::string error;
};


static std::ostream& PrintHexWithColons(std::ostream& s, const BYTE* data, DWORD size) {
    for (DWORD i = 0; i < size; ++i) {
        if (i > 0) {
            s << ':';
        }
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s << std::dec;
}

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

int main()
{
    std::cout << "Hello World!\n";
    //    1: This is the root of the OID tree, which is managed by the International Organization for Standardization(ISO).
    //    2 : This indicates that the OID is part of the ISO member body.
    //    643 : This is the country code for Russia, as assigned by ISO.
    //  Filtering certificates by an OID that starts with "1.2.643" means you are looking for certificates that 
    // use cryptographic algorithms defined by Russian standards.

    try 
	{
		auto res = GetCertificates("1.2.643"); // Example filter string

		if (!res.empty())
		{
			for (const auto& cert : res)
			{
				std::cout << "Friendly Name: " << cert.friendlyName << std::endl;
				std::cout << "Thumbprint: ";
				PrintHexWithColons(std::cout, cert.thumbprint.data(), cert.thumbprint.size()) << std::endl;
			}
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
    return 0;
}
