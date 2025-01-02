#include <windows.h>
#include <stdio.h>

int main() {
    
    const char* dllPath = "dhanushgowda.dll";

    // Load the DLL into process
    HMODULE hDll = LoadLibraryA(dllPath);

    // Get the address of the exported function
    FARPROC func_addr = GetProcAddress(hDll, "coolboy");
    if (func_addr == NULL) {
        printf("Error: Could not find the function");
        FreeLibrary(hDll);
        return 1;
    }

    // Cast the function address to a function pointer
    typedef void (*COOLBOY_FUNC)(); 
    COOLBOY_FUNC coolboy_func = (COOLBOY_FUNC)func_addr;

   
    coolboy_func(); 

   
    FreeLibrary(hDll);
    return 0;
}
