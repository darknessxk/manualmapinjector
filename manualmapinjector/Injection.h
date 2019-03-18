#pragma once

#include <Windows.h>	// 
#include <iostream>		// 
#include <fstream>		// file helper
#include "FunctionsTemplate.h"
#include "Macros.h"

struct MANUALMAPDATA {
	pLoadLibraryA	pLoadLib;
	pGetProcAddress pGetProcAddr;
	HINSTANCE		hModule;
};

void __stdcall Shellcode(MANUALMAPDATA* pData);
bool ManualMap(HANDLE hProc, LPCSTR targetDll);