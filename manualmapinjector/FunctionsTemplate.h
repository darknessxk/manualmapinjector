#ifndef __FUNCTIONSTEMPLATE_H__
#define __FUNCTIONSTEMPLATE_H__

#pragma once

#include <Windows.h>

using pLoadLibraryA = HINSTANCE(WINAPI*)(const char * libFile);
using pGetProcAddress = UINT_PTR(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using pDllMain = BOOL(WINAPI*)(LPVOID hDll, DWORD dwReason, LPVOID pReserved);

#endif