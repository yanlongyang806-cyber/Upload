// VEHSkipPatch.cpp  (x64 DLL)
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

constexpr SIZE_T TARGET_OFFSET = 0x00E5EE7E; // 如需调整后我会告诉你
constexpr SIZE_T TARGET_RANGE  = 0x500;

static PVOID g_vectHandler = nullptr;
static ULONG_PTR g_moduleBase = 0;

static void log_append(const char* fmt, ...)
{
    FILE* f = nullptr;
    fopen_s(&f, "C:\\temp\\veh_patch_log.txt", "a");
    if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ep)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR rip = (ULONG_PTR)ep->ContextRecord->Rip;
    ULONG_PTR start = g_moduleBase + TARGET_OFFSET;
    ULONG_PTR end   = start + TARGET_RANGE;

    if (rip >= start && rip <= end) {
        log_append("[VEH] ACCESS_VIOLATION at RIP=0x%p in [%p - %p], attempting skip", (void*)rip, (void*)start, (void*)end);

        __try {
            ULONG_PTR* rsp_ptr = (ULONG_PTR*)(ep->ContextRecord->Rsp);
            ULONG_PTR ret_addr = *rsp_ptr;
            if (ret_addr == 0) {
                log_append("[VEH] return address is zero, cannot skip safely");
                return EXCEPTION_CONTINUE_SEARCH;
            }
            ep->ContextRecord->Rip = ret_addr;
            ep->ContextRecord->Rsp += sizeof(ULONG_PTR);
            log_append("[VEH] Skipped bad instruction, set RIP=0x%p, new RSP=0x%p", (void*)ret_addr, (void*)ep->ContextRecord->Rsp);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_append("[VEH] Exception while trying to skip - abort");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool InstallHandler()
{
    HMODULE hMod = GetModuleHandleA("worldserver.exe");
    if (!hMod) {
        log_append("[InstallHandler] worldserver.exe not loaded");
        return false;
    }
    g_moduleBase = (ULONG_PTR)hMod;
    log_append("[InstallHandler] module base = 0x%p, target offset = 0x%zX", (void*)g_moduleBase, TARGET_OFFSET);

    if (g_vectHandler) return true;
    g_vectHandler = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!g_vectHandler) {
        log_append("[InstallHandler] AddVectoredExceptionHandler failed");
        return false;
    }
    log_append("[InstallHandler] VEH installed");
    return true;
}

void UninstallHandler()
{
    if (g_vectHandler) {
        RemoveVectoredExceptionHandler(g_vectHandler);
        g_vectHandler = nullptr;
        log_append("[UninstallHandler] VEH removed");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateDirectoryA("C:\\temp", NULL);
        log_append("[DllMain] attached, installing handler...");
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)[](LPVOID)->DWORD {
            Sleep(1000);
            InstallHandler();
            return 0;
        }, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        UninstallHandler();
        log_append("[DllMain] detached");
        break;
    }
    return TRUE;
}
