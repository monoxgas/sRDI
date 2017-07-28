#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"
#include <windows.h>
#include <intrin.h>

// we declare some common stuff in here...

#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI * REFLECTIVELOADER)(LPVOID lpParameter, LPVOID lpLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen, BOOL exitThread);
typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef HMODULE(WINAPI * LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI * GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI * VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID(WINAPI * EXITTHREAD)(DWORD);
typedef DWORD(NTAPI  * NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

/** NOTE: module hashes are computed using all-caps unicode strings */
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define EXITTHREAD_HSAH					0x60E0CEEF
#define NTFLUSHINSTRUCTIONCACHE_HASH			0x534C0AB8
#define RTLEXITUSERTHREAD_HASH				0xFF7F061A // Vista+

#define IMAGE_REL_BASED_ARM_MOV32A		5
#define IMAGE_REL_BASED_ARM_MOV32T		7

#define ARM_MOV_MASK					(DWORD)(0xFBF08000)
#define ARM_MOV_MASK2					(DWORD)(0xFBF08F00)
#define ARM_MOVW						0xF2400000
#define ARM_MOVT						0xF2C00000

#define HASH_KEY						13

typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_FREE_BLOCK 
{
	struct _PEB_FREE_BLOCK * pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;

#pragma warning( push )
#pragma warning( disable : 4214 ) // nonstandard extension
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;
#pragma warning(pop)

// Redefine Win32 function signatures. This is necessary because the output
// of GetProcAddressWithHash is cast as a function pointer. Also, this makes
// working with these functions a joy in Visual Studio with Intellisense.
typedef HMODULE (WINAPI *FuncLoadLibraryA) (
	_In_z_	LPTSTR lpFileName
);

typedef HANDLE (WINAPI *FuncCreateFile) (
	_In_     LPCTSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
);

typedef BOOL (WINAPI *FuncWriteFile)(
	_In_        HANDLE       hFile,
	_In_        LPCVOID      lpBuffer,
	_In_        DWORD        nNumberOfBytesToWrite,
	_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef int (WINAPI *FuncMessageBox)(
	_In_opt_ HWND    hWnd,
	_In_opt_ LPSTR lpText,
	_In_opt_ LPSTR lpCaption,
	_In_     UINT    uType
	);

typedef BOOL(*EXPORTFUNC)(LPVOID, DWORD);

// Write the logic for the primary payload here
// Normally, I would call this 'main' but if you call a function 'main', link.exe requires that you link against the CRT
// Rather, I will pass a linker option of "/ENTRY:ExecutePayload" in order to get around this issue.
ULONG_PTR ExecutePayload(ULONG_PTR uiLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen)
{
	#pragma warning( push )
	#pragma warning( disable : 4055 ) // Ignore cast warnings

	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	EXITTHREAD pExitThread = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	PIMAGE_DATA_DIRECTORY directory = NULL;
	PIMAGE_EXPORT_DIRECTORY exports = NULL;
	int idx;
	DWORD nameSearchIndex;
	DWORD *nameRef = NULL;
	WORD *ordinal = NULL;
	PCSTR pTempChar;
	DWORD dwCalculatedFunctionHash;

	EXPORTFUNC f = NULL;

	// the initial location of this image in memory
	//ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// exit code for current thread
	DWORD dwExitCode = 1;

	pLoadLibraryA = (LOADLIBRARYA)GetProcAddressWithHash(0x726774c);
	pGetProcAddress = (GETPROCADDRESS)GetProcAddressWithHash(0x7802f749);
	pVirtualAlloc = (VIRTUALALLOC)GetProcAddressWithHash(0xe553a458);
	pExitThread = (EXITTHREAD)GetProcAddressWithHash(0xa2a1de0);
	pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GetProcAddressWithHash(0x945cb1af);

	
	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;
	
	while (uiValueA--)
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// STEP 3: load in all of our sections...
	
	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}
	
	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);
		
		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal && uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{

				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
				
				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	
	// STEP 5: process all of our images relocations...
	
	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point
	
	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)

	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);

	if (dwFunctionHash) {
		
		do
		{
			directory = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (directory->Size == 0)
				break;

			exports = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + directory->VirtualAddress);
			if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
				break;

			// search function name in list of exported names
			idx = -1;
			nameRef = (DWORD *)(uiBaseAddress + exports->AddressOfNames);
			ordinal = (WORD *)(uiBaseAddress + exports->AddressOfNameOrdinals);
			for (nameSearchIndex = 0; nameSearchIndex < exports->NumberOfNames; nameSearchIndex++, nameRef++, ordinal++) {

				pTempChar = (char *)(uiBaseAddress + (*nameRef));
				dwCalculatedFunctionHash = 0;

				do
				{
					dwCalculatedFunctionHash = ROTR32(dwCalculatedFunctionHash, 13);
					dwCalculatedFunctionHash += *pTempChar;
					pTempChar++;
				} while (*(pTempChar - 1) != 0);

				if (dwFunctionHash == dwCalculatedFunctionHash)
				{
					idx = *ordinal;
					break;
				}
			}
			if (idx == -1)
				break;

			// AddressOfFunctions contains the RVAs to the "real" functions
			f = (EXPORTFUNC)(uiBaseAddress + (*(DWORD *)(uiBaseAddress + exports->AddressOfFunctions + (idx * 4))));
			if (!f(lpUserData, nUserdataLen))
				break;

			dwExitCode = 0;
		} while (0);
	}

	return uiBaseAddress; //Atempt to return a handle to the module
}