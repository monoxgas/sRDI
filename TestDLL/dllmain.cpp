// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>


HANDLE hSSThread;
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
	return MessageBoxA(NULL, "I'm Leaving!", "Goodbye", 0);
}

extern "C" __declspec(dllexport) BOOL SayHello(LPVOID lpUserdata, DWORD nUserdataLen)
{
	return MessageBoxA(NULL, "I'm alive!", "Hello", 0);
}

