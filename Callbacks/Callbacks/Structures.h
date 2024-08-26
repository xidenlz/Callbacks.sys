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
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_ORDINAL_FLAG 0x80000000
#define IMAGE_ORDINAL_MASK 0xFFFF
#define JMP_REL32_OPCODE 0xE9
#ifndef _WINNT_
#define _WINNT_


#ifndef _IMAGE_DATA_DIRECTORY_DEFINED
typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
#define _IMAGE_DATA_DIRECTORY_DEFINED
#endif

#ifndef _IMAGE_OPTIONAL_HEADER_DEFINED
typedef struct _IMAGE_OPTIONAL_HEADER
{
    USHORT                  Magic;
    UCHAR                   MajorLinkerVersion;
    UCHAR                   MinorLinkerVersion;
    ULONG                   SizeOfCode;
    ULONG                   SizeOfInitializedData;
    ULONG                   SizeOfUninitializedData;
    ULONG                   AddressOfEntryPoint;
    ULONG                   BaseOfCode;
    ULONG                   BaseOfData;
    ULONG                   ImageBase;
    ULONG                   SectionAlignment;
    ULONG                   FileAlignment;
    USHORT                  MajorOperatingSystemVersion;
    USHORT                  MinorOperatingSystemVersion;
    USHORT                  MajorImageVersion;
    USHORT                  MinorImageVersion;
    USHORT                  MajorSubsystemVersion;
    USHORT                  MinorSubsystemVersion;
    ULONG                   Win32VersionValue;
    ULONG                   SizeOfImage;
    ULONG                   SizeOfHeaders;
    ULONG                   CheckSum;
    USHORT                  Subsystem;
    USHORT                  DllCharacteristics;
    ULONG                   SizeOfStackReserve;
    ULONG                   SizeOfStackCommit;
    ULONG                   SizeOfHeapReserve;
    ULONG                   SizeOfHeapCommit;
    ULONG                   LoaderFlags;
    ULONG                   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY     DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;
#define _IMAGE_OPTIONAL_HEADER_DEFINED
#endif

#endif // _WINNT_

typedef struct _IMAGE_IMPORT_BY_NAME
{
    USHORT Hint;
    CHAR Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA
{
    union
    {
        PVOID Function;
        ULONG Ordinal;
        PIMAGE_IMPORT_BY_NAME AddressOfData;
    } u1;
} IMAGE_THUNK_DATA, * PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        ULONG Characteristics;
        ULONG OriginalFirstThunk;
    } DESCRIPTOR_UNION_NAME;  
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, * PIMAGE_IMPORT_DESCRIPTOR;




typedef struct _LOADED_MODULE_INFO
{
    UNICODE_STRING ImgFullName;
    PVOID ImgBase;
    SIZE_T ImgSize;
    LIST_ENTRY lEntry;
} LOADED_MODULE_INFO, * PLOADED_MODULE_INFO;

LIST_ENTRY ModuleList;

typedef unsigned char BYTE;
typedef BYTE* PBYTE;



typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


typedef struct _IMAGE_OPTIONAL_HEADER32
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONG BaseOfData;
    ULONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG SizeOfStackReserve;
    ULONG SizeOfStackCommit;
    ULONG SizeOfHeapReserve;
    ULONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16]; 
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONG64 ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG SizeOfStackReserve;
    ULONG SizeOfStackCommit;
    ULONG SizeOfHeapReserve;
    ULONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16]; 
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;


//typedef struct _IMAGE_NT_HEADERS32
//{
//    ULONG Signature;
//    IMAGE_FILE_HEADER FileHeader;
//    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
//} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;


//NTSTATUS ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewProtect, PULONG OldProtect);
