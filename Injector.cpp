// Injector.cpp - CreateRemoteThread 注入器 (x64)
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <cstdio>

DWORD FindProcessId(const char* processName) {
    PROCESSENTRY32 pe32; pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) { CloseHandle(hSnap); return pe32.th32ProcessID; }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return 0;
}

int main() {
    const char* dllPath = "C:\\patch\\VEHSkipPatch.dll";
    const char* procName = "worldserver.exe";

    DWORD pid = FindProcessId(procName);
    if (!pid) { printf("Process not found\n"); return 1; }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { printf("OpenProcess failed %u\n", GetLastError()); return 1; }

    SIZE_T len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remote, dllPath, len, nullptr);

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC loadLib = GetProcAddress(hKernel, "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, nullptr);
    if (!hThread) { printf("CreateRemoteThread failed %u\n", GetLastError()); VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); CloseHandle(hProc); return 1; }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    printf("Injection finished\n");
    return 0;
}
