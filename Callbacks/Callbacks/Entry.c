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
#include "Memory.hpp"
#include "CallBacks.h"

NTSTATUS UnloadDriver(PDRIVER_OBJECT DrvObj)
{
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(RegisterProcessesCallbacks, TRUE);
	if (!NT_SUCCESS(status))
	{
		PrintError("Failed to unregister callback, status = 0x%X\n", status);
	}

	status = PsRemoveLoadImageNotifyRoutine(RegisterImgCallbacks);

	if (!NT_SUCCESS(status))
	{
		PrintError("Failed to unregister Image callback, status = 0x%X\n", status);
	}
	
	FreeModules();


	if (DrvObj->DeviceObject)
	{
		IoDeleteDevice(DrvObj->DeviceObject);
	}

	Print("Driver unloaded\n");


	return status;
}




NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	NTSTATUS status = STATUS_SUCCESS;

	InitializeListHead(&ModuleList);

	status = PsSetCreateProcessNotifyRoutine(RegisterProcessesCallbacks, FALSE);
	if (!NT_SUCCESS(status))
	{
		PrintError("Failed to register callback, status = 0x%X\n", status);
		return status;
	}

	status = PsSetLoadImageNotifyRoutine(RegisterImgCallbacks);
	if (!NT_SUCCESS(status))
	{
		PrintError("Failed to register image callback, status = 0x%X\n", status);
		return status;
	}

	InitializeListHead(&ModuleList);

	DrvObj->DriverUnload = UnloadDriver;
	Print("Driver loaded\n");

	return status;
}