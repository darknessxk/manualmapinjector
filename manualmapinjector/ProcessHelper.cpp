#include "ProcessHelper.h"
#include <iostream>

DWORD FindProcessByName(LPCSTR lpProcName) {
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		std::cout << "Snap Creation Failed: " << GetLastError() << std::endl;
		return 0;
	}

	bool bRet = Process32First(hSnap, &PE32);

	while (bRet) {

		if (!strcmp(lpProcName, PE32.szExeFile)) {
			return PE32.th32ProcessID;
		}

		bool bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);
	free(&PE32);

	return 0;
}