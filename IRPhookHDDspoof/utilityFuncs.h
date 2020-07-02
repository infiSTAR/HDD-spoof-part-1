#pragma once
#include "Undocumented.h"
#include <intrin.h>


PVOID64 SwapPointer(PVOID* ptr1, PVOID* ptr2)
{

	if (MmIsAddressValid(*ptr1) && MmIsAddressValid(*ptr2))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;

		__writecr0(cr0);

		_disable();

		PVOID64 old = *ptr1;
		*ptr1 = *ptr2;
		*ptr2 = old;
		return old;

		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	return TRUE;
}


KIRQL disableWP()
{
	KIRQL	tempirql = KeRaiseIrqlToDpcLevel();

	ULONG64  cr0 = __readcr0();

	cr0 &= 0xfffffffffffeffff;

	__writecr0(cr0);

	_disable();

	return tempirql;

}

void enableWP(KIRQL		tempirql)
{
	ULONG64	cr0 = __readcr0();

	cr0 |= 0x10000;

	_enable();

	__writecr0(cr0);

	KeLowerIrql(tempirql);
}

DWORD64 placeJMP(DWORD64 injectionAddress, DWORD64 jmpDestination, UCHAR* oldBytes)
{
	if (MmIsAddressValid(injectionAddress))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;

		__writecr0(cr0);

		_disable();

		RtlCopyMemory((PVOID64)oldBytes, (PVOID64)injectionAddress, 12); //save old bytes

		/*
			mov rax, jmpAddress
			jmp rax
		*/

		BYTE		shellCode[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		RtlCopyMemory((PVOID64)(shellCode + 2), (PVOID64)&jmpDestination, 8);
		RtlCopyMemory((PVOID64)injectionAddress, shellCode, 12); // copy the shellcode to destination

		DbgPrint("Jmp injected ! \n");

		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	else
	{
		DbgPrint("invalid address %p, place jmp failed!!\n", (PVOID64)injectionAddress);
	}
	return TRUE;
}



PVOID getDriverBaseAddress(OUT PULONG pSize, const char* driverName)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;


	PVOID			DriverBase = 0;
	ULONG64			DriverSize = 0;


	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x45454545); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);

	if (NT_SUCCESS(Status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{
			//list the module names:

			DbgPrint("Image name: %s\n", pMod[i].FullPathName + pMod[i].OffsetToFileName);
			// path name plus some amount of characters will lead to the name itself
			const char* DriverName = (const char*)pMod[i].FullPathName + pMod[i].OffsetToFileName;

			if (strcmp(DriverName, driverName) == 0)
			{
				DbgPrint("found driver\n");


				DriverBase = pMod[i].ImageBase;
				DriverSize = pMod[i].ImageSize;

				DbgPrint("Disk.sys Size : %i\n", DriverSize);
				DbgPrint("Disk.sys Base : %p\n", DriverBase);


				if (arrayOfModules)
					ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'




				*pSize = DriverSize;
				return DriverBase;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'



	*pSize = DriverSize;
	return (PVOID)DriverBase;
}


