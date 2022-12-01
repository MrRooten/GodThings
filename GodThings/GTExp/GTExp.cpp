#include "Process.h" 

int main() {
	ProcessManager* mgr = new ProcessManager();
	mgr->SetAllProcesses();
	for (auto& s : mgr->processesMap) {
		wprintf(L"%d: %s\n", s.first, s.second->GetProcessName().c_str());
	}
	return 0;
}