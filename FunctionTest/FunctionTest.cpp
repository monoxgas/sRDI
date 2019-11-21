// FunctionTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string>

#define SRDI_CLEARHEADER 0x1
#define SRDI_CLEARMEMORY 0x2
#define SRDI_OBFUSCATEIMPORTS 0x4

#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)

FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName)
{
	if (hModule == NULL || lpProcName == NULL)
		return NULL;

	PIMAGE_NT_HEADERS ntHeaders = RVA(PIMAGE_NT_HEADERS, hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dataDir->Size)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY exportDir = RVA(PIMAGE_EXPORT_DIRECTORY, hModule, dataDir->VirtualAddress);
	if (!exportDir->NumberOfNames || !exportDir->NumberOfFunctions)
		return NULL;

	PDWORD expName = RVA(PDWORD, hModule, exportDir->AddressOfNames);
	PWORD expOrdinal = RVA(PWORD, hModule, exportDir->AddressOfNameOrdinals);
	LPCSTR expNameStr;

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++) {

		expNameStr = RVA(LPCSTR, hModule, *expName);

		if (!expNameStr)
			break;

		if (!_stricmp(lpProcName, expNameStr)) {
			DWORD funcRva = *RVA(PDWORD, hModule, exportDir->AddressOfFunctions + (*expOrdinal * 4));
			return RVA(FARPROC, hModule, funcRva);
		}
	}

	return NULL;
}


DWORD GetFileContents(LPCSTR filename, LPSTR *data, DWORD &size)
{
	std::FILE *fp = std::fopen(filename, "rb");

	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		*data = (LPSTR)malloc(size + 1);
		fread(*data, size, 1, fp);
		fclose(fp);
		return true;
	}
	return false;
}

#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

DWORD HashFunctionName(LPSTR name) {
	DWORD hash = 0;

	do
	{
		hash = ROTR32(hash, 13);
		hash += *name;
		name++;
	} while (*(name - 1) != 0);

	return hash;
}

extern "C" ULONG_PTR LoadDLL(ULONG_PTR uiLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen, DWORD flags);

int main()
{
	LPSTR buffer = NULL;
	DWORD bufferSize = 0;

	HMODULE test = LoadLibraryA("User32.dll"); // For MessageBox Testing

#ifdef _WIN64
	LPCSTR fileName = "../bin/TestDLL_x64.dll";
#else
	LPCSTR fileName = "../bin/TestDLL_x86.dll";
#endif

	DWORD result = GetFileContents(fileName, &buffer, bufferSize);

	if (!result || buffer == NULL) {
		printf("[!] Cannot read file.");
		return 1;
	}

	LoadDLL(
		(ULONG_PTR)buffer,
		HashFunctionName("SayGoodbye"),
		NULL, 0, 
		SRDI_CLEARHEADER | SRDI_CLEARMEMORY // | SRDI_OBFUSCATEIMPORTS | (3 << 16)
	);

    return 0;
}

