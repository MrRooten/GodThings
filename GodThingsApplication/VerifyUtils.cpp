#include "VerifyUtils.h"
#include "mscat.h"
#include "utils.h"
#include "StringUtils.h"
DWORD VerifyCatalogSignatureAddition(_In_ LPCWSTR pwszSourceFile,
    _In_ bool UseStrongSigPolicy, GTWString& catalogFile);
SignatureInfomation* VerifyEmbeddedSignature(LPCWSTR pwszSourceFile) {
    LONG lStatus;
    DWORD dwLastError;
    SignatureInfomation* info = new SignatureInfomation();
    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    /*WinTrustData.pCatalog = &catalogInfo;*/

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:

        info->info = L"The file is signed and the signature "
            L"was verified.";
        info->isSignature = true;
        break;

    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            info->info = L"The file is not signed.";
            info->isSignature = false;
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            info->info = L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n";
            info->isSignature = false;
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        info->info = L"The signature is present, but specifically "
            L"disallowed.";
        info->isSignature = true;
        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        info->info = L"The signature is present, but not "
            L"trusted.\n";
        info->isSignature = true;
        break;

    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        info->info = L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n";
        info->isSignature = false;
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wchar_t s[30] = { 0 };
        wsprintfW(s, L"Error is: 0x%x.", lStatus);
        info->info = s;
        info->isSignature = true;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);
    if (info->isSignature == false) {
        GTWString path = pwszSourceFile;
        GTWString s = path + L"\\..\\AppxMetadata\\CodeIntegrity.cat";
        auto result = VerifyCatalogSignatureAddition(pwszSourceFile, false, s);
        if (result == 0) {
            info->isSignature = true;
            info->info = L"Catalog verify";
        }
    }
    return info;
}


DWORD VerifyCatalogSignature(_In_ LPCWSTR pwszSourceFile,
    _In_ bool UseStrongSigPolicy)
{
    DWORD Error = ERROR_SUCCESS;
    bool Found = false;
    HCATADMIN CatAdminHandle = NULL;
    HCATINFO CatInfoHandle = NULL;
    DWORD HashLength = 0;
    PBYTE HashData = NULL;
    CERT_STRONG_SIGN_PARA SigningPolicy = {};
    HANDLE FileHandle = CreateFileW(pwszSourceFile,
        GENERIC_READ,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (UseStrongSigPolicy != false)
    {
        SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
        SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
        SigningPolicy.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
        if (!CryptCATAdminAcquireContext2(
            &CatAdminHandle,
            NULL,
            BCRYPT_SHA256_ALGORITHM,
            &SigningPolicy,
            0))
        {
            Error = GetLastError();
            goto Cleanup;
        }
    }
    else
    {
        if (!CryptCATAdminAcquireContext2(
            &CatAdminHandle,
            NULL,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0))
        {
            if (!CryptCATAdminAcquireContext2(
                &CatAdminHandle,
                NULL,
                BCRYPT_SHA256_ALGORITHM,
                NULL,
                0)) {
                Error = GetLastError();
                goto Cleanup;
            }
            
        }
    }

    // Get size of hash to be used
    if (!CryptCATAdminCalcHashFromFileHandle2(
        CatAdminHandle,
        FileHandle,
        &HashLength,
        NULL,
        NULL))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
    if (HashData == NULL)
    {
        Error = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    // Generate hash for a give file
    if (!CryptCATAdminCalcHashFromFileHandle2(
        CatAdminHandle,
        FileHandle,
        &HashLength,
        HashData,
        NULL))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    // Find the first catalog containing this hash
    CatInfoHandle = NULL;
    CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
        CatAdminHandle,
        HashData,
        HashLength,
        0,
        &CatInfoHandle);

    while (CatInfoHandle != NULL)
    {
        CATALOG_INFO catalogInfo = {};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        Found = true;

        if (!CryptCATCatalogInfoFromContext(
            CatInfoHandle,
            &catalogInfo,
            0))
        {
            Error = GetLastError();
            break;
        }

        wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

        // Look for the next catalog containing the file's hash
        CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
            CatAdminHandle,
            HashData,
            HashLength,
            0,
            &CatInfoHandle);
    }

    if (Found != true)
    {
        wprintf(L"Hash was not found in any catalogs.\n");
        Error = 1;
    }

Cleanup:
    if (CatAdminHandle != NULL)
    {
        if (CatInfoHandle != NULL)
        {
            CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
        }

        CryptCATAdminReleaseContext(CatAdminHandle, 0);
    }

    if (HashData != NULL)
    {
        HeapFree(GetProcessHeap(), 0, HashData);
    }
    CloseHandle(FileHandle);
    return Error;
}
#include <cassert>
BytesBuffer Sha256(PBYTE bytes, size_t n) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    BYTE* pbHash = NULL;
    DWORD dwHashLen;
    DWORD dwCount;
    auto flag = CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (flag == false) {
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    flag = CryptCreateHash(
        hCryptProv,
        CALG_SHA_256,
        0,
        0,
        &hHash);
    if (flag == false) {
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    flag = CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwCount, 0);
    if (flag == false) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    pbHash = (PBYTE)malloc(dwHashLen);
    if (pbHash == NULL) {
        LOG_ERROR_REASON(L"");
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        return std::string();
    }

    flag = CryptHashData(
        hHash,
        bytes,
        n,
        CRYPT_USERDATA
    );

    flag = CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0);
    
    BytesBuffer result((char*)pbHash, dwHashLen);
    free(pbHash);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    return result;
}

BytesBuffer Sha1(PBYTE bytes, size_t n) {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    BYTE* pbHash = NULL;
    DWORD dwHashLen;
    DWORD dwCount;
    auto flag = CryptAcquireContext(
        &hCryptProv,
        NULL,
        MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (flag == false) {
        LOG_ERROR_REASON(L"");
    }

    flag = CryptCreateHash(
        hCryptProv,
        CALG_SHA1,
        0,
        0,
        &hHash);
    if (flag == false) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    flag = CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwCount, 0);
    if (flag == false) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    pbHash = (PBYTE)malloc(dwHashLen);
    if (pbHash == NULL) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }

    flag = CryptHashData(
        hHash,
        bytes,
        n,
        CRYPT_USERDATA
    );
    if (flag == false) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }


    flag = CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0);
    if (flag == false) {
        if (hHash)
            CryptDestroyHash(hHash);
        if (hCryptProv)
            CryptReleaseContext(hCryptProv, 0);
        LOG_ERROR_REASON(L"");
        return std::string();
    }


    BytesBuffer result((char*)pbHash, dwHashLen);
    free(pbHash);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    return result;
}


#define BUFSIZE 1024
#define MD5LEN  16

BytesBuffer Md5File(HANDLE hFile) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL bResult = FALSE;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    if (INVALID_HANDLE_VALUE == hFile) {
        throw GTException("not a valid HANDLE");
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT)) {
        GTString result = "CryptAccquireContext failed " + StringUtils::ws2s(GetLastErrorAsString());
        throw GTException(result.c_str());
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        GTString result = "CryptAccquireContext failed " + StringUtils::ws2s(GetLastErrorAsString());
        throw GTException(result.c_str());
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            GTString result = "CryptAccquireContext failed " + StringUtils::ws2s(GetLastErrorAsString());
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            throw GTException(result.c_str());
        }
    }

    if (!bResult)
    {
        GTString result = "Read File " + StringUtils::ws2s(GetLastErrorAsString());
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        throw GTException(result.c_str());
    }

    cbHash = MD5LEN;
    GTString md5Result;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        char key[3] = {0};
        for (DWORD i = 0; i < cbHash; i++)
        {
            snprintf(key, 3, "%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
            md5Result += key;
        }
        
    }
    else
    {
        GTString result = "CryptGetHashParam failed: " + StringUtils::ws2s(GetLastErrorAsString());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw GTException(result.c_str());
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return md5Result;
}

#include "StringUtils.h"

GTString Base64Encode(PBYTE bytes, size_t n) {
    DWORD size = 0;
    auto flag = CryptBinaryToStringA(
        bytes,
        n,
        CRYPT_STRING_BASE64,
        NULL,
        &size
    );
    //assert(flag == true);
    auto base64 = (LPSTR)malloc(size);
    if (base64 == NULL) {
        LOG_ERROR_REASON(L"");
        return std::string();
    }
    flag = CryptBinaryToStringA(
        bytes,
        n,
        CRYPT_STRING_BASE64,
        base64,
        &size
    );
    if (flag == false) {
        LOG_ERROR_REASON(L"");
        if (base64 == NULL) {
            delete base64;
        }
        return std::string();
    }
    assert(base64 != NULL);
    auto result = StringUtils::Trim(base64);
    return result;
}



DWORD VerifyCatalogSignatureAddition(_In_ LPCWSTR pwszSourceFile,
    _In_ bool UseStrongSigPolicy,GTWString &catalogFile) {
    DWORD Error = ERROR_SUCCESS;
    bool Found = false;
    HCATADMIN CatAdminHandle = NULL;
    HCATINFO CatInfoHandle = NULL;
    DWORD HashLength = 0;
    PBYTE HashData = NULL;
    CERT_STRONG_SIGN_PARA SigningPolicy = {};
    HCATINFO CatAddtionHandle = NULL;
    HANDLE FileHandle = CreateFileW(pwszSourceFile,
        GENERIC_READ,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (UseStrongSigPolicy != false)
    {
        SigningPolicy.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
        SigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
        SigningPolicy.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
        if (!CryptCATAdminAcquireContext2(
            &CatAdminHandle,
            NULL,
            BCRYPT_SHA256_ALGORITHM,
            &SigningPolicy,
            0))
        {
            Error = GetLastError();
            goto Cleanup;
        }
    }
    else
    {
        if (!CryptCATAdminAcquireContext2(
            &CatAdminHandle,
            NULL,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0))
        {
            if (!CryptCATAdminAcquireContext2(
                &CatAdminHandle,
                NULL,
                BCRYPT_SHA256_ALGORITHM,
                NULL,
                0)) {
                Error = GetLastError();
                goto Cleanup;
            }

        }
    }

    // Get size of hash to be used
    if (!CryptCATAdminCalcHashFromFileHandle2(
        CatAdminHandle,
        FileHandle,
        &HashLength,
        NULL,
        NULL))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    HashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, HashLength);
    if (HashData == NULL)
    {
        Error = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    // Generate hash for a give file
    if (!CryptCATAdminCalcHashFromFileHandle2(
        CatAdminHandle,
        FileHandle,
        &HashLength,
        HashData,
        NULL))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    // Find the first catalog containing this hash
    CatInfoHandle = NULL;
    CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
        CatAdminHandle,
        HashData,
        HashLength,
        0,
        &CatInfoHandle);

    while (CatInfoHandle != NULL)
    {
        CATALOG_INFO catalogInfo = {};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        Found = true;

        if (!CryptCATCatalogInfoFromContext(
            CatInfoHandle,
            &catalogInfo,
            0))
        {
            Error = GetLastError();
            break;
        }

        //wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

        // Look for the next catalog containing the file's hash
        CatInfoHandle = CryptCATAdminEnumCatalogFromHash(
            CatAdminHandle,
            HashData,
            HashLength,
            0,
            &CatInfoHandle);
    }

    if (Found != true)
    {
        //wprintf(L"Hash was not found in any catalogs.\n");
        Error = 1;
    }

    if (Found == true) {
        goto Cleanup;
    }
    CatAddtionHandle = CryptCATAdminAddCatalog(CatAdminHandle, (PWSTR)catalogFile.c_str(), NULL, 0);
    if (CatAddtionHandle == NULL) {
        Error = GetLastError();
        goto Cleanup;
    }

    CatAddtionHandle = CryptCATAdminEnumCatalogFromHash(
        CatAdminHandle,
        HashData,
        HashLength,
        0,
        &CatAddtionHandle);

    while (CatAddtionHandle != NULL)
    {
        CATALOG_INFO catalogInfo = {};
        catalogInfo.cbStruct = sizeof(catalogInfo);
        Found = true;

        if (!CryptCATCatalogInfoFromContext(
            CatAddtionHandle,
            &catalogInfo,
            0))
        {
            Error = GetLastError();
            break;
        }

        wprintf(L"Hash was found in catalog %s\n\n", catalogInfo.wszCatalogFile);

        // Look for the next catalog containing the file's hash
        CatAddtionHandle = CryptCATAdminEnumCatalogFromHash(
            CatAdminHandle,
            HashData,
            HashLength,
            0,
            &CatAddtionHandle);

        if (Found == true) {
            Error = 0;
            goto Cleanup;
        }

        if (Found == false) {
            Error = GetLastError();
            goto Cleanup;
        }
    }

Cleanup:
    if (CatAdminHandle != NULL)
    {
        if (CatInfoHandle != NULL)
        {
            CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatInfoHandle, 0);
        }

        if (CatAddtionHandle != NULL) {
            CryptCATAdminReleaseCatalogContext(CatAdminHandle, CatAddtionHandle, 0);
            CryptCATAdminRemoveCatalog(CatAdminHandle, (PWSTR)catalogFile.c_str(), 0);
        }
        CryptCATAdminReleaseContext(CatAdminHandle, 0);
    }

    if (HashData != NULL)
    {
        HeapFree(GetProcessHeap(), 0, HashData);
    }
    CloseHandle(FileHandle);


    return Error;
}