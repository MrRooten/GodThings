#include "FireWallInfo.h"

FwRuleMgr::FwRuleMgr() {

}
// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        wprintf(L"CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:
    return hr;
}

/**
* Iterate Firewall Rule, this function will auto delete the pointer, if error occur will throw GTException

*/
void FwRuleMgr::IterateFwRule(FwCallback callback) {
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0;
    CComVariant var;

    IUnknown* pEnumerator = NULL;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2* pNetFwPolicy2 = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;

    long fwRuleCount;
    char msg[1024] = { 0 };
    // Initialize COM.
    //hrComInit = CoInitializeEx(
    //    0,
    //    COINIT_APARTMENTTHREADED
    //);

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            snprintf(msg, 1024, "CoInitializeEx failed : 0x%08lx", hrComInit);
            goto Cleanup;
        }
    }

    // Retrieve INetFwPolicy2
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr))
    {
        goto Cleanup;
    }

    // Retrieve INetFwRules
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr))
    {
        snprintf(msg, 1024, "get_Rules failed: 0x%08lx", hr);
        goto Cleanup;
    }

    // Obtain the number of Firewall rules
    hr = pFwRules->get_Count(&fwRuleCount);
    if (FAILED(hr))
    {
        snprintf(msg, 1024, "get_Count failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Iterate through all of the rules in pFwRules
    pFwRules->get__NewEnum(&pEnumerator);

    if (pEnumerator)
    {
        hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);
    }

    while (SUCCEEDED(hr) && hr != S_FALSE)
    {
        var.Clear();
        hr = pVariant->Next(1, &var, &cFetched);

        if (S_FALSE != hr)
        {
            if (SUCCEEDED(hr))
            {
                hr = var.ChangeType(VT_DISPATCH);
            }
            if (SUCCEEDED(hr))
            {
                hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
            }

            if (SUCCEEDED(hr))
            {
                // Output the properties of this rule
                
                auto rule = FwRule::NewFwRule(pFwRule);
                if (rule == NULL) {
                    continue;
                }
                auto ok = callback(rule);
                if (ok == false) {
                    delete rule;
                    break;
                }
                delete rule;
                pFwRule->Release();
                pFwRule = NULL;
            }
        }
    }

Cleanup:

    // Release pFwRule
    if (pFwRule != NULL)
    {
        pFwRule->Release();
    }

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }



    if (msg[0] != 0) {
        throw GTException(msg);
    }

}

FwRule::FwRule() {
    
}

FwRule* FwRule::NewFwRule(INetFwRule* rule) {
    auto result = new FwRule();
    variant_t InterfaceArray;
    variant_t InterfaceString;

    VARIANT_BOOL bEnabled;
    BSTR bstrVal;

    long lVal = 0;
    long lProfileBitmask = 0;

    NET_FW_RULE_DIRECTION fwDirection;
    NET_FW_ACTION fwAction;

    struct ProfileMapElement
    {
        NET_FW_PROFILE_TYPE2 Id;
        LPCWSTR Name;
    };

    ProfileMapElement ProfileMap[3];
    ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
    ProfileMap[0].Name = L"Domain";
    ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
    ProfileMap[1].Name = L"Private";
    ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
    ProfileMap[2].Name = L"Public";

    if (SUCCEEDED(rule->get_Name(&bstrVal)) && bstrVal != NULL) {
        result->name = bstrVal;
    }

    if (SUCCEEDED(rule->get_Description(&bstrVal)) && bstrVal != NULL) {
        result->description = bstrVal;
    }

    if (SUCCEEDED(rule->get_ApplicationName(&bstrVal)) && bstrVal != NULL) {
        result->appName = bstrVal;
    }

    if (SUCCEEDED(rule->get_ServiceName(&bstrVal)) && bstrVal != NULL) {
        result->serviceName = bstrVal;
    }

    if (SUCCEEDED(rule->get_Protocol(&lVal))) {
        switch (lVal) {
        case NET_FW_IP_PROTOCOL_TCP:
            result->protocol = L"TCP";
            break;
        case NET_FW_IP_PROTOCOL_UDP:
            result->protocol = L"UDP";
            break;
        default:
            break;
        }

        if (lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6) {
            if (SUCCEEDED(rule->get_LocalPorts(&bstrVal)) && bstrVal != NULL) {
                result->localPorts = bstrVal;
            }

            if (SUCCEEDED(rule->get_RemotePorts(&bstrVal)) && bstrVal != NULL) {
                result->remotePorts = bstrVal;
            }
        }
    }

    if (SUCCEEDED(rule->get_LocalAddresses(&bstrVal)) && bstrVal != NULL) {
        result->localAddresses = bstrVal;
    }

    if (SUCCEEDED(rule->get_RemoteAddresses(&bstrVal)) && bstrVal != NULL) {
        result->remoteAddresses = bstrVal;
    }

    if (SUCCEEDED(rule->get_Profiles(&lProfileBitmask))) {
        
    }

    if (SUCCEEDED(rule->get_Direction(&fwDirection))) {
        switch (fwDirection)
        {
        case NET_FW_RULE_DIR_IN:

            result->direction = FwDirection::In;
            break;

        case NET_FW_RULE_DIR_OUT:

            result->direction = FwDirection::Out;
            break;

        default:

            break;
        }
    }
    
    if (SUCCEEDED(rule->get_Action(&fwAction))) {
        switch (fwAction)
        {
        case NET_FW_ACTION_BLOCK:
            result->action = FwAction::Block;
            break;

        case NET_FW_ACTION_ALLOW:
            result->action = FwAction::Allow;
            break;

        default:
            break;
        }
    }

    if (SUCCEEDED(rule->get_Interfaces(&InterfaceArray))) {
        
    }

    if (SUCCEEDED(rule->get_InterfaceTypes(&bstrVal)) && bstrVal != NULL) {

    }

    if (SUCCEEDED(rule->get_Enabled(&bEnabled))) {
        result->enable = bEnabled;
    }

    if (SUCCEEDED(rule->get_Grouping(&bstrVal))) {

    }
    return result;
}

GTWString& FwRule::GetName() {
    return this->name;
}

GTWString& FwRule::GetDescription() {
    return this->description;
}

GTWString& FwRule::GetAppName() {
    return this->appName;
}

GTWString& FwRule::GetServiceName()
{
    return this->serviceName;
}

GTWString& FwRule::GetProtocol()
{
    return this->protocol;
}

GTWString& FwRule::GetLocalPorts()
{
    return this->localAddresses;
}

GTWString& FwRule::GetRemotePorts()
{
    return this->remotePorts;
}

GTWString& FwRule::GetLocalAddresses()
{
    return this->localAddresses;
}

GTWString& FwRule::GetRemoteAddresses()
{
    return this->remoteAddresses;
}

FwAction FwRule::GetAction()
{
    return this->action;
}

FwDirection FwRule::GetDirection()
{
    return this->direction;
}

bool FwRule::IsEnable()
{
    return this->enable;
}

FwAction::FwAction()
{
}

FwAction::FwAction(action a) {
    this->a = a;
}

GTWString FwAction::WString() {
    if (this->a == Block) {
        return L"Block";
    }
    else {
        return L"Allow";
    }
}

FwDirection::FwDirection()
{
}

FwDirection::FwDirection(direction d)
{
    this->d = d;
}

GTWString FwDirection::WString() {
    if (this->d == In) {
        return L"In";
    }
    else {
        return L"Out";
    }
}
