#pragma once
#include "Memory.hpp"


BOOLEAN ReportImg(PUNICODE_STRING ImgFullName)
{
	if (!ImgFullName)
		return FALSE;

	for (int i = 0; i < RTL_NUMBER_OF(Images); i++)
	{
		UNICODE_STRING Img = { 0 };
		USHORT Offset = ImgFullName->Length - Images[i].Length;

		if (Offset < 0)
			continue;

		RtlInitUnicodeString(&Img, ImgFullName->Buffer + Offset / sizeof(WCHAR));
		if (RtlEqualUnicodeString(&Img, &Images[i], TRUE))
			return TRUE;
	}

	return FALSE;
}




VOID RegisterProcessesCallbacks(HANDLE Useless, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(Useless);
	if (Create)
	{
		Print("Process created: PID = %lu\n", (ULONG)(ULONG_PTR)ProcessId);
	}
	else
	{
		Print("Process terminated: PID = %lu\n", (ULONG)(ULONG_PTR)ProcessId);
	}
}




VOID RegisterImgCallbacks(PUNICODE_STRING ImgName, HANDLE ProcessId, PIMAGE_INFO ImgInfo)
{
	Print("Image loaded %wZ with process %lu\n", ImgName, (ULONG)(ULONG_PTR)ProcessId);

	if (ReportImg(ImgName))
	{
		PrintFound("Found Module");
		if (ImgName && ImgInfo)
		{
			PLOADED_MODULE_INFO ModuleInfo = (PLOADED_MODULE_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(LOADED_MODULE_INFO), 'modl');

			if (ModuleInfo)
			{
				RtlInitUnicodeString(&ModuleInfo->ImgFullName, ImgName->Buffer);

				ModuleInfo->ImgBase = ImgInfo->ImageBase;
				ModuleInfo->ImgSize = ImgInfo->ImageSize;

				InsertTailList(&ModuleList, &ModuleInfo->lEntry);

				PrintFound("Found Sniffy driver: %wZ\n", ImgName);
				PrintFound("Driver base: %p\n", ImgInfo->ImageBase);
				PrintFound("Image size: %llu\n", ImgInfo->ImageSize);


				DumpImg(ModuleInfo);
			}
		}
	}
}





VOID QueryModules()
{
	PLIST_ENTRY pEntry = ModuleList.Flink;
	while (pEntry != &ModuleList)
	{
		PLOADED_MODULE_INFO m_Info = CONTAINING_RECORD(pEntry, LOADED_MODULE_INFO, lEntry);
		Print("Module: %wZ, Base Address: %p, Size: %lu\n", m_Info->ImgFullName, m_Info->ImgBase, m_Info->ImgSize);

		pEntry = pEntry->Flink;
	}
}




VOID FreeModules()
{
	PLIST_ENTRY pEntry = ModuleList.Flink;

	while (pEntry != &ModuleList)
	{
		PLOADED_MODULE_INFO m_Info = CONTAINING_RECORD(pEntry, LOADED_MODULE_INFO, lEntry);
		pEntry = pEntry->Flink;

		RemoveEntryList(&m_Info->lEntry);
		ExFreePoolWithTag(m_Info, 'modl');
	}
}
