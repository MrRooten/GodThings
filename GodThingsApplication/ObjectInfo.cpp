#include "ObjectInfo.h"
pNtQueryObject NtQueryObject = NULL;
std::wstring ObjectInfo::GetObjectName(HANDLE hObject) {
    if (hObject == NULL) {
        return L"";
    }
    std::wstring res;
    
    if (NtQueryObject == NULL) {
        NtQueryObject = (pNtQueryObject)GetNativeProc("NtQueryObject");
    }
    if (NtQueryObject == NULL) {
        return L"";
    }
    OBJECT_NAME_INFORMATION* name = NULL;
    DWORD size = 0;
    NTSTATUS status = NtQueryObject(hObject, ObjectNameInformation, NULL,0, &size);
    if (status != 0) {
        if (status == 0xc0000004) {
            name = (OBJECT_NAME_INFORMATION*)LocalAlloc(GPTR,size);
            if (name == NULL) {
                goto cleanup;
            }
            status = NtQueryObject(hObject, ObjectNameInformation, name, size, &size);
            if (status != 0) {
                goto cleanup;
            }
        }
        else {
            goto cleanup;
        }
    }

    if (name==NULL||name->Name.Buffer == NULL) {
        return L"";
    }
    res = name->Name.Buffer;
cleanup:
    SetLastError(NtStatusHandler(status));
    LocalFree(name);
    return res;
}
bool ObjectInfo::IsValidObject(HANDLE hObject) {
    DWORD out;
    if (GetHandleInformation(hObject, &out)) {
        return true;
    }

    return false;
}
OBJECT_BASIC_INFORMATION* ObjectInfo::GetObjectInfo(HANDLE hObject) {
    if (hObject == NULL) {
        return NULL;
    }

    if (NtQueryObject == NULL) {
        NtQueryObject = (pNtQueryObject)GetNativeProc("NtQueryObject");
    }
    if (NtQueryObject == NULL) {
        return NULL;
    }

    OBJECT_BASIC_INFORMATION* result = new OBJECT_BASIC_INFORMATION();
    DWORD size = sizeof(OBJECT_BASIC_INFORMATION);
    NTSTATUS status = NtQueryObject(hObject, ObjectBasicInformation, result, size, &size);
    SetLastError(NtStatusHandler(status));
    if (status != 0) {
        delete result;
        return NULL;
    }
    return result;
}


#include "utils.h"

std::wstring ObjectInfo::GetTypeName(HANDLE hObject) {
    if (hObject == NULL) {
        
        return L"";
    }
    std::wstring res;
    if (NtQueryObject == NULL) {
        NtQueryObject = (pNtQueryObject)GetNativeProc("NtQueryObject");
    }
    if (NtQueryObject == NULL) {
        return L"";
    }
    OBJECT_TYPE_INFORMATION* type = NULL;
    DWORD size = 0;
    NTSTATUS status = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &size);
    if (status != 0) {
        if (status == 0xc0000004) {
            type = (OBJECT_TYPE_INFORMATION*)LocalAlloc(GPTR,size);
            status = NtQueryObject(hObject, ObjectTypeInformation, type, size, &size);
            if (status != 0) {
                goto cleanup;
            }
        }
        else {
            goto cleanup;
        }
    }

    if (type != NULL && type->TypeName.Buffer == NULL) {
        return L"";
    }
    res = type->TypeName.Buffer;
cleanup:
    SetLastError(NtStatusHandler(status));
    LocalFree(type);
    return res;
}
