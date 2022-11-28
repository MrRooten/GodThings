#include "VerifyUtils.h"
#include "mscat.h"
#include "utils.h"
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

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    /*
    WINTRUST_CATALOG_INFO catalogInfo;
    memset(&catalogInfo, 0, sizeof(catalogInfo));
    catalogInfo.cbStruct = sizeof(catalogInfo);
    catalogInfo.pcwszCatalogFilePath = pwszSourceFile;
    catalogInfo.pcwszMemberFilePath = NULL; // Information->FileName
    HFILE FileHandle = OpenFile()
    catalogInfo.hMemberFile = FileHandle;
    catalogInfo.pcwszMemberTag = fileHashTag->Buffer;
    catalogInfo.pbCalculatedFileHash = fileHash;
    catalogInfo.cbCalculatedFileHash = fileHashLength;
    catalogInfo.hCatAdmin = catAdminHandle;
    // Initialize the WinVerifyTrust input data structure.
    */

    // Default all fields to 0.
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
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
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