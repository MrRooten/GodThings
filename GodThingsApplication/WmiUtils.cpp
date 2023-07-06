#include "WmiUtils.h"
#include <format>
#include "StringUtils.h"
#include "utils.h"
WmiTaker::WmiTaker() {
    //auto hres = CoInitializeEx(NULL, COINIT_MULTITHREADED);


    auto hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        auto msg = std::format("Failed to initialize Security. Error code = 0x{}", hres);


        throw GTException(msg.c_str());
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        auto msg = std::format("Failed to Create Instance. Error code = 0x{}", hres);

        throw GTException(msg.c_str());
    }

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        auto msg = std::format("Failed to Connect to Server. Error code = 0x{}", hres);
        pLoc->Release();
        throw GTException(msg.c_str());
    }

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        auto msg = std::format("Failed CoSetProxyBlanket. Error code = 0x{}", hres);
        pSvc->Release();
        pLoc->Release();
        throw GTException(msg.c_str());
    }
}

WmiTaker::WmiResult WmiTaker::take(const wchar_t* sql) {
    IEnumWbemClassObject* pEnumerator = NULL;
    auto hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        (WCHAR*)sql,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        auto msg = std::format("Failed to Query `{}`. Error code = 0x{}", hres, StringUtils::ws2s(sql).c_str());
        throw GTException(msg.c_str());
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    WmiResult ret;
    
    while (pEnumerator)
    {
        std::map<GTWString, WmiTaker::WmiVariable> result;
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        
        SAFEARRAY* psaNames = NULL;
        hres = pclsObj->GetNames(NULL, WBEM_FLAG_ALWAYS, NULL, &psaNames);
        if (FAILED(hres)) {
            auto msg = std::format("Failed to GetNames. Error code = 0x{}", hres);
            throw GTException(msg.c_str());
        }

        long lLower, lUpper;
        BSTR PropName = NULL;
        SafeArrayGetLBound(psaNames, 1, &lLower);
        SafeArrayGetUBound(psaNames, 1, &lUpper);

        for (long i = lLower; i <= lUpper; i++)
        {
            // Get this property.
            hres = SafeArrayGetElement(
                psaNames,
                &i,
                &PropName);
            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(PropName, 0, &vtProp, 0, 0);
            if (vtProp.vt == VT_BSTR) {
                result[PropName] = vtProp.bstrVal;
            }
            else if (vtProp.vt == VT_I4) {
                result[PropName] = vtProp.intVal;
            }
            VariantClear(&vtProp);
            SysFreeString(PropName);
        }
        ret.push_back(result);
        pclsObj->Release();
    }
    
    return ret;

}

WmiTaker::~WmiTaker()
{
    pLoc->Release();
    pSvc->Release();
}
