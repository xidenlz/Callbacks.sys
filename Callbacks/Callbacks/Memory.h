
/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>

*/

#pragma once
#include <ntddk.h>
#include "Debug.h"
#include "Structures.h"


UNICODE_STRING Images[] = {
    RTL_CONSTANT_STRING(L"eaanticheat.sys") // Sniffy driver 
};


//VOID ExShellCode(PVOID FuncAddr, PVOID Addr)
//{
//    ULONG_PTR jmp = (ULONG_PTR)Addr - ((ULONG_PTR)FuncAddr + sizeof(BYTE) + sizeof(ULONG_PTR));
//    ULONG oldProtect;
//    NTSTATUS status = ZwProtectVirtualMemory(ZwCurrentProcess(), &FuncAddr, sizeof(BYTE), +sizeof(ULONG_PTR), PAGE_EXECUTE_READ, &oldProtect);
//
//    if (!NT_SUCCESS(status))
//    {
//        PrintError("Failed to change memory protection\n");
//        return;
//    }
//
//    *(BYTE*)FuncAddr = JMP_REL32_OPCODE;
//    *(ULONG_PTR*)((BYTE*)FuncAddr + sizeof(BYTE)) = (ULONG_PTR)jmp;
//
//    ZwProtectVirtualMemory(ZwCurrentProcess(), &FuncAddr, sizeof(BYTE) + sizeof(ULONG_PTR), oldProtect, &oldProtect);
//
//    Print("jmp to %p\n", Addr);
//}



VOID DumpImg(PLOADED_MODULE_INFO ModuleInfo)
{
    PVOID pDump = ExAllocatePoolWithTag(NonPagedPool, ModuleInfo->ImgSize, 'dmpT');
    if (pDump == NULL)
    {
        PrintError("Failed to allocate memory\n");
        return;
    }

    RtlCopyMemory(pDump, ModuleInfo->ImgBase, ModuleInfo->ImgSize);

    UNICODE_STRING FilePath = RTL_CONSTANT_STRING(L"\\??\\C:\\Sniffy.bin");

    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE hFile;

    InitializeObjectAttributes(&ObjAttr, &FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = ZwCreateFile(&hFile, GENERIC_WRITE, &ObjAttr, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status))
    {
        ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pDump, (ULONG)ModuleInfo->ImgSize, NULL, NULL);
        ZwClose(hFile);

        Print("Memory saved to C:\\Sniffy.bin\n");
    }
    else
    {
        PrintError("Failed to dump, status: 0x%X\n", status);
    }

    ExFreePoolWithTag(pDump, 'dmpT');
}



VOID GetImports(PVOID DriverBase)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DriverBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)DriverBase + DosHeader->e_lfanew);
    DriverBase = Images;

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        PrintError("Invalid PE signature\n");
        return;
    }

    ULONG ImportDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (ImportDirRVA == 0)
    {
        PrintError("No import directory found\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)DriverBase + ImportDirRVA);

    while (ImportDescriptor->Name != 0)
    {
        PCHAR Win32Module = (PCHAR)((PBYTE)DriverBase + ImportDescriptor->Name);
        Print("Importing from: %s\n", Win32Module);

        PIMAGE_THUNK_DATA o_FirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)DriverBase + ImportDescriptor->DESCRIPTOR_UNION_NAME.OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)DriverBase + ImportDescriptor->FirstThunk);

        while (o_FirstThunk->u1.AddressOfData != 0)
        {
            if (!(o_FirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)DriverBase + (ULONG_PTR)o_FirstThunk->u1.AddressOfData);
                Print("Imported function: %s at address %p\n", ImportByName->Name, FirstThunk->u1.Function);
            }
            o_FirstThunk++;
            FirstThunk++;
        }
        ImportDescriptor++;
    }
}




