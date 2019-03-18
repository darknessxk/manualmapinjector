#include "Injection.h"
#define MAGIC_HEADER 0x5A4D //MZ


bool ManualMap(HANDLE hProc, LPCSTR lpTargetDll) {
	PBYTE					pSrcData = nullptr;
	PIMAGE_NT_HEADERS		pOldNtHeader = nullptr;
	PIMAGE_OPTIONAL_HEADER	pOldOptHeader = nullptr;
	PIMAGE_FILE_HEADER		pOldFileHeader = nullptr;
	PBYTE					pTargetBase = nullptr;

	DWORD dwCheck = 0;
	if (!GetFileAttributesA(lpTargetDll)) {
		std::cout << "File not found" << std::endl;
		return false;
	}

	std::ifstream fs(lpTargetDll, std::ios::binary | std::ios::ate);

	if (fs.fail())
	{
		std::cout << "Open fail op failed: " << fs.rdstate() << std::endl;
		fs.close();
		return GetLastError();
	}

	auto fsize = fs.tellg();
	if (fsize < 0x1000) {
		std::cout << "File size is invalid" << std::endl;
		fs.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(fsize)];
	if (!pSrcData) {
		std::cout << "Memory allocation failed" << std::endl;
		fs.close();
		return false;
	}

	fs.seekg(0, std::ios::beg);
	fs.read(reinterpret_cast<char*>(pSrcData), fsize);
	fs.close(); // end our file operations here

	if (reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData)->e_magic != MAGIC_HEADER) {
		std::cout << "Invalid file type" << std::endl;
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "Invalid platform" << std::endl;
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		std::cout << "Invalid platform" << std::endl;
		delete[] pSrcData;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<PBYTE>(VirtualAllocEx(hProc, reinterpret_cast<PVOID>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase) {
		pTargetBase = reinterpret_cast<PBYTE>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase) {
			std::cout << "Memory allocation failed (target process error): " << GetLastError() << std::endl;
			delete[] pSrcData;
			return false;
		}
	}

	MANUALMAPDATA mmapData{ 0 };

	mmapData.pLoadLib = LoadLibraryA;
	mmapData.pGetProcAddr = reinterpret_cast<pGetProcAddress>(GetProcAddress);

	auto *pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, 0)) {
				std::cout << "Failed to map sections: " << GetLastError() << std::endl;
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, &mmapData, sizeof(mmapData));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, 0);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		std::cout << "Memory allocation failed (target process error): " << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, 0);
	WriteProcessMemory(hProc, pTargetBase, &mmapData, sizeof(mmapData), 0);

	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, 0);
	if (!hThread) {
		std::cout << "Thread creation failed (target process error): " << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = 0;
	while (!hCheck) {
		MANUALMAPDATA dataCheck{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &dataCheck, sizeof(dataCheck), 0);
		hCheck = dataCheck.hModule;
		Sleep(100);
	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
}

void __stdcall Shellcode(MANUALMAPDATA* pData) {
	if (!pData)
		return;

	PBYTE pBase = reinterpret_cast<PBYTE>(pData);

	PIMAGE_OPTIONAL_HEADER pOpt = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pData)->e_lfanew)->OptionalHeader;

	pLoadLibraryA _LoadLibA			= pData->pLoadLib;
	pGetProcAddress _GetProcAddr	= pData->pGetProcAddr;
	pDllMain _DllMain				= reinterpret_cast<pDllMain>(pBase + pOpt->AddressOfEntryPoint);
	
	PBYTE pLocationD = pBase - pOpt->ImageBase;

	if (pLocationD) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return;
		}

		PIMAGE_BASE_RELOCATION pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress) {
			UINT uEntriesCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD pRelativeInfo = reinterpret_cast<PWORD>(pRelocData + 1);

			for (UINT i; i != uEntriesCount; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR *pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(pLocationD);
				}
			}

			pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(pRelocData) + pRelocData->SizeOfBlock);

		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDesc->Name) {
			PCHAR szMod = reinterpret_cast<PCHAR>(pBase + pImportDesc->Name);
			HINSTANCE hDll = _LoadLibA(szMod);

			ULONG_PTR *pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR *pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			//Import DLL functions that are required by dll
			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddr(hDll, reinterpret_cast<PCHAR>(*pThunkRef & 0xFFFF));
				}
				else {
					PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBase + (*pThunkRef));
					
					*pFuncRef = _GetProcAddr(hDll, pImport->Name);
				}
			}
			++pImportDesc;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		PIMAGE_TLS_DIRECTORY pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK *pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
}