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

FARPROC GetProcAddressR(UINT_PTR uiLibraryAddress, LPCSTR lpProcName)
{
	FARPROC fpResult = NULL;

	if (uiLibraryAddress == NULL)
		return NULL;

	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// get the VA of the modules NT Header
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the VA of the export directory
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	// get the VA for the array of addresses
	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

	// get the VA for the array of name pointers
	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

	// get the VA for the array of name ordinals
	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	// test if we are importing by name or by ordinal...
	if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
	{
		// import by ordinal...

		// use the import ordinal (- export ordinal base) as an index into the array of addresses
		uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

		// resolve the address for this imported function
		fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
	}
	else
	{
		// import by name...
		DWORD dwCounter = pExportDirectory->NumberOfNames;
		while (dwCounter--)
		{
			char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

			// test if we have a match...
			if (strcmp(cpExportedFunctionName, lpProcName) == 0)
			{
				// use the functions name ordinal as an index into the array of name pointers
				uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

				// calculate the virtual address for the function
				fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

				// finish...
				break;
			}

			// get the next exported function name
			uiNameArray += sizeof(DWORD);

			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}

	return fpResult;
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
		HashFunctionName("SayHello"),
		NULL, 0, 
		SRDI_CLEARHEADER | SRDI_CLEARMEMORY | SRDI_OBFUSCATEIMPORTS | (3 << 16)
	);

    return 0;
}

