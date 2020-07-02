#include "utilityFuncs.h"
#include <ntdddisk.h>


extern POBJECT_TYPE* IoDriverObjectType;

PIRP				interceptedIRP = 0x6969;
PDEVICE_OBJECT		interceptedDeviceObj = 0x69420;
UCHAR				oldDiskBytes[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
PDRIVER_DISPATCH	targetAddr;
DWORD64				diskDriverBase;


typedef struct IoCompletionStruct
{
	PVOID	oldContext;
	PIO_COMPLETION_ROUTINE	oldCompletionRoutine;
	PVOID	systemBuffer;

}IO_COMPLETION_STRUCT, * PIO_COMPLETION_STRUCT;




NTSTATUS customDiskCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_COMPLETION_STRUCT Context)
{
	DbgPrint("custom completion routine called \n");
	/*
			spoof shit here










	*/


	if (Irp->StackCount > 1 && Context->oldCompletionRoutine)
	{
		Context->oldCompletionRoutine(DeviceObject, Irp, Context->oldContext);
		DbgPrint("address of old completion routine is: %p \n", Context->oldCompletionRoutine);
	}
	else
	{
		DbgPrint("old completion routine not called. \n");
	}
	return STATUS_SUCCESS;
}






#pragma optimize("", off)
NTSTATUS spoofDisk()
{
	/*	padding for register grabbing shellcode*/

	int a1 = 123123;	 //8 byte padding
	int a2 = 123123;	 
	int a3 = 123123;	 
	int a4 = 123123;	 


	DbgPrint("IRP location is: %p \n", interceptedIRP);
	DbgPrint("DEVICE_OBJECT location is: %p \n", interceptedDeviceObj);
	DbgPrint("system buffer location is: %p \n", interceptedIRP->AssociatedIrp.SystemBuffer);

	//		restore old bytes in disk.sys		
	DWORD size;


	KIRQL	tempIRQL = disableWP();
	RtlCopyMemory((DWORD64)diskDriverBase + 0xf9d2, oldDiskBytes, 12);	//restore bytes
	enableWP(tempIRQL);

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(interceptedIRP);

	STORAGE_PROPERTY_QUERY* requestBuffer = interceptedIRP->AssociatedIrp.SystemBuffer;

	/* change io completion routine here
`	1. save old context, old routine
	2. set control to invoke on success
	3. write new context, new routine
	*/


	DbgPrint("Io control code is: %p \n", IoStackLocation->Parameters.DeviceIoControl.IoControlCode);

	PIO_COMPLETION_STRUCT newContext = NULL;

	switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_STORAGE_QUERY_PROPERTY:
		DbgPrint("systembuffer->propertyID is: %i \n", requestBuffer->PropertyId);
		if (requestBuffer->PropertyId == StorageDeviceProperty)
		{
			IoStackLocation->Control = 0;
			IoStackLocation->Control |= SL_INVOKE_ON_SUCCESS;

			PVOID OldContext = IoStackLocation->Context;

			IoStackLocation->Context = (PVOID)ExAllocatePool(NonPagedPool, sizeof(IO_COMPLETION_STRUCT));

			PIO_COMPLETION_STRUCT newContext = (PIO_COMPLETION_STRUCT)IoStackLocation->Context;

			newContext->oldCompletionRoutine = IoStackLocation->CompletionRoutine;

			DbgPrint("address of old completion routine is: %p \n", newContext->oldCompletionRoutine);
			DbgPrint("address of old completion routine is: %p \n", IoStackLocation->CompletionRoutine);

			newContext->oldContext = OldContext;

			IoStackLocation->CompletionRoutine = (PIO_COMPLETION_ROUTINE)customDiskCompletion;
		}
	default:

		break;
	}

	DbgPrint("IRP->associatedIRP->masterirp is: %p \n", interceptedIRP->AssociatedIrp.MasterIrp);

	return targetAddr(interceptedDeviceObj, interceptedIRP);
}
#pragma optimize("", on)


DWORD64		placeDiskHook()
{
	KIRQL   tempirql = KeRaiseIrqlToDpcLevel();
	int size;
	diskDriverBase = getDriverBaseAddress(&size, "disk.sys");
	targetAddr = (DWORD64)(diskDriverBase) + 0xf9d2;


	//spoofdisk + some bytes to skip padding
	placeJMP((DWORD64)(diskDriverBase) + 0xf9d2, (DWORD64)(&spoofDisk) + 10, oldDiskBytes);
	placeJMP((DWORD64)(diskDriverBase) + 0xf9d2, (DWORD64)(&spoofDisk) + 10, oldDiskBytes);
	//f9d2 is an arbitrary addres
	

	UNICODE_STRING diskDriverName;
	DRIVER_OBJECT* diskDriverObject = NULL;

	RtlInitUnicodeString(&diskDriverName, L"\\Driver\\disk");
	ObReferenceObjectByName(&diskDriverName, OBJ_KERNEL_HANDLE, 0, GENERIC_ALL, *IoDriverObjectType, KernelMode, 0, &diskDriverObject);


	if (diskDriverObject)
	{
		SwapPointer(&diskDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], &targetAddr);
		DbgPrint("device object location of diskdriverobject is: %p \n", diskDriverObject->DeviceObject);
		
	}
	

	
	KeLowerIrql(tempirql);

	return STATUS_SUCCESS;
}


void	placeSpoofDiskcode()
{
	UCHAR		grabRDXcode[]  = "\x52\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x8F\x00";	//PIRP is stored in RDX
	UCHAR		grabRCXcode[]  = "\x51\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x8F\x00";	//PDEVICE_OBJECT is stored in RCX

	PVOID64		iinterceptedIRP = (PVOID64)&interceptedIRP;
	PVOID64		iinterceptedDeviceObj = (PVOID64)&interceptedDeviceObj;


	RtlCopyMemory(grabRDXcode + 3, (PVOID64)(&iinterceptedIRP), sizeof(PIRP));
	RtlCopyMemory((DWORD64)(&spoofDisk) + 10, grabRDXcode, 13);



	RtlCopyMemory(grabRCXcode + 3, (PVOID64)(&iinterceptedDeviceObj), sizeof(PDEVICE_OBJECT));
	RtlCopyMemory((DWORD64)(&spoofDisk) + 23, grabRCXcode, 13);

	//placeJMP(spoofdisk + 0x37, ... );
}


NTSTATUS DriverEntry(DRIVER_OBJECT* driverObject, PUNICODE_STRING registryPath)
{
	placeDiskHook();
	placeSpoofDiskcode();
}



NTSTATUS RealDriverEntry(DRIVER_OBJECT* driverObject, PUNICODE_STRING registryPath)
{
	DbgPrint("driver start\n");
	DriverEntry(driverObject, registryPath);
}