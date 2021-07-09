#include <Windows.h>
#include "io.hardlock.emulator.h"
#include "io.hardlock.hooks.h"
#include "nativecore/debug.h"
__declspec(dllexport) void io_hardlock() {};



int __stdcall DllMain(HINSTANCE hinstDLL, unsigned int fdwReason, void* lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DBG_printfA("[io.hardlock]: Starting...");
        if (LoadHardLockInfo("hardlock.ini") && InitHooks()) {
            DBG_printfA("[io.hardlock]: Started!");
            return TRUE;
        }else{
            DBG_printfA("[io.hardlock]: Failed to Start!");
        }
        return FALSE;
    }
    return TRUE;
}



