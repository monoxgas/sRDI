#include <Windows.h>
#include <stdio.h>

DWORD threadID;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "DLLMain!", "We've started.", 0);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//extern "C" to prevent C++ name mangling
extern "C" __declspec(dllexport) BOOL SayGoodbye(LPVOID lpUserdata, DWORD nUserdataLen)
{
	try {
		int i = 0, j = 1;
		j /= i;   // This will throw a SE (divide by zero).
	}
	catch (...) {
		MessageBoxA(NULL, "C++ Exception Thrown!", "Caught it", 0);
	}

	MessageBoxA(NULL, "I'm Leaving!", "Goodbye", 0);
	
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL SayHello(LPVOID lpUserdata, DWORD nUserdataLen)
{
	if (nUserdataLen) {
		DWORD length = 10 + nUserdataLen;
		LPSTR greeting = (LPSTR)malloc(length);
		sprintf_s(greeting, length, "Hello %s!", (LPSTR)lpUserdata);
		MessageBoxA(NULL, greeting, "Hello", 0);
		free(greeting);
	}
	else {
		MessageBoxA(NULL, "I'm alive!", "Hello", 0);
	}

	return TRUE;
}

