#include "pch.h"
#include "ModuleCLI.h"
#include <string>

namespace GodAgent {
    NativeModuleCLI::NativeModuleCLI(NativeModule* ntModule) {
        this->Name = gcnew String(ntModule->Name.c_str());
        this->Class = gcnew String(ntModule->Class.c_str());
        this->Path = gcnew String(ntModule->Path.c_str());
        this->Type = gcnew String(ntModule->Type.c_str());
        this->Description = gcnew String(ntModule->Description.c_str());
        this->_module = ntModule;
    }

    ResultSetCLI^ NativeModuleCLI::ModuleRun() {
        ResultSet* resultSet = this->_module->ModuleRun();
        ResultSetCLI^ resultSetCLI = gcnew ResultSetCLI(resultSet);
        delete resultSet;
        return resultSetCLI;
    }

    PythonModuleCLI::PythonModuleCLI(PythonModule* pyModule) {
        this->Name = gcnew String(pyModule->Name.c_str());
        this->Class = gcnew String(pyModule->Class.c_str());
        this->Path = gcnew String(pyModule->Path.c_str());
        this->Type = gcnew String(pyModule->Type.c_str());
        this->Description = gcnew String(pyModule->Description.c_str());
    }

    ResultSetCLI^ PythonModuleCLI::ModuleRun() {
        ResultSet* resultSet = this->_module->ModuleRun();
        ResultSetCLI^ resultSetCLI = gcnew ResultSetCLI(resultSet);
        delete resultSet;
        return resultSetCLI;
    }

    ResultSetCLI::ResultSetCLI(ResultSet* resultSet) {
        if (resultSet->dataSet.size() == 0) {
            return;
        }

        for (const auto& item : resultSet->dataSet) {
            String^ fieldName = gcnew String(item.first.c_str());
            ArrayList^ fieldRecords = gcnew ArrayList();
            for (const auto& _fieldRecord : item.second) {
                fieldRecords->Add(gcnew String(_fieldRecord.c_str()));
            }
            this->dataSet->Add(fieldName, fieldRecords);
        }


    }

    Hashtable^ ResultSetCLI::GetDataSet() {
        return this->dataSet;
    }
    ModuleMgrCLI::ModuleMgrCLI() {
        ModuleMgr* mgr = ModuleMgr::GetMgr();
        mgr->LoadModules();
        this->_moduleList = gcnew ArrayList();
        for (auto module : mgr->modules) {
            ModuleCLI^ moduleCLI;
            if (module->Type == L"Python") {
                moduleCLI = gcnew PythonModuleCLI((PythonModule*)module);
            }
            else if (module->Type == L"Native") {
                moduleCLI = gcnew NativeModuleCLI((NativeModule*)module);
            }
            this->_moduleList->Add(moduleCLI);
        }
    }
    ArrayList^ ModuleMgrCLI::GetModuleList() {
        return this->_moduleList;
    }
    
}