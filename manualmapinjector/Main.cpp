#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>
#include "Injection.h"
#include "ProcessHelper.h"

/*
TODO: Load raw binary in memory (done)
TODO: Map Sections in our target (done)
TODO: Inject Loader Shell code (done)
TODO: Relocate memory (done)
TODO: Fix target dll imports (done)
TODO: Execute TLS Callbacks (done)
TODO: Call our DLLMain (done)
TODO: Clean garbage memory (done)
*/

int main(int argc, char** argv) {
	if (argc < 2) {
		std::cout << "Missing target dll and/or target process example" << std::endl;
		std::cout << "manualmapinjector.exe mydll.dll calc.exe" << std::endl;
		exit(GetLastError());
	}

	DWORD dwProc = 0;
	dwProc = FindProcessByName(argv[2]);
	if (dwProc == 0) {
		std::cout << "Something went wrong maybe we are unable to find this process: " << argv[2] << std::endl;
		exit(GetLastError());
	}
	else {
		std::cout << "Process found" << std::endl;
	}
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProc);
	
	if (!hProc) {
		std::cout << "Something went wrong while we tried to open this process: " << argv[2] << std::endl;
		exit(GetLastError());
	}

	//Manual Map our dll
	if (!ManualMap(hProc, argv[1])) {
		std::cout << "Something went wrong while we tried to manual map this dll: " << argv[1] << std::endl;
		exit(GetLastError());
	}
	else {
		std::cout << "Manual Mapping Success" << std::endl;
	}

	CloseHandle(hProc);

	exit(0);
}