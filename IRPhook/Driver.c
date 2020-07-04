#include "utils.h"
#include <ntdddisk.h>


extern POBJECT_TYPE* IoDriverObjectType;
PDRIVER_DISPATCH	oldDispatch;

char	newserial[20] = "spoofed-by-JGUO5258";


typedef struct IoCompletionStruct
{
	PVOID	oldContext;
	PIO_COMPLETION_ROUTINE	oldCompletionRoutine;
	PSTORAGE_DEVICE_DESCRIPTOR	requestBuffer;
	DWORD	OutBufferLength;
	DWORD	signature;

}IO_COMPLETION_STRUCT, * PIO_COMPLETION_STRUCT;






NTSTATUS customDiskCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_COMPLETION_STRUCT Context)
{

	if (Context->requestBuffer->SerialNumberOffset > 0 &&
		Context->requestBuffer->SerialNumberOffset < Context->OutBufferLength)
	{
		char* SerialNumber = ((char*)Context->requestBuffer) + Context->requestBuffer->SerialNumberOffset;
		DbgPrint("SerialNumber: %s\n", SerialNumber);

		RtlCopyMemory(SerialNumber, newserial, sizeof(char) * 20);

		DbgPrint("spoofed!! new serial Number is: %s \n", SerialNumber);
	}
	else
	{
		DbgPrint("invalid!!! Context->requestBuffer->SerialNumberOffset is: %p \n", Context->requestBuffer->SerialNumberOffset);
		DbgPrint("invalid!!! Context->OutBufferLength is: %p \n", Context->OutBufferLength);
	}


	if (Irp->StackCount > 1 && Context->oldCompletionRoutine)
	{

		if (Irp->Flags & IRP_DEALLOCATE_BUFFER)	//just in case it frees something invalid later on
		{
			Irp->Flags &= ~IRP_DEALLOCATE_BUFFER;	//set 5th bit to 0
		}

		return Context->oldCompletionRoutine(DeviceObject, Irp, Context->oldContext);

		Irp->IoStatus.Status = STATUS_SUCCESS;
	}
	else
	{
		DbgPrint("old completion routine not called. \n");
	}
	return STATUS_SUCCESS;
}







NTSTATUS spoofDisk(PDEVICE_OBJECT	deviceObject, PIRP	 Irp)
{

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	STORAGE_PROPERTY_QUERY* requestBuffer = Irp->AssociatedIrp.SystemBuffer;


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

			newContext->oldContext = OldContext;

			newContext->signature = 0x99991111;

			newContext->requestBuffer = requestBuffer;

			newContext->OutBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

			IoStackLocation->CompletionRoutine = (PIO_COMPLETION_ROUTINE)customDiskCompletion;
		}
	default:

		break;
	}

	if (Irp->Flags & IRP_DEALLOCATE_BUFFER)
	{
		Irp->Flags &= ~IRP_DEALLOCATE_BUFFER;	//set 5th bit to 0
		DbgPrint("cleared IRP_DEALLOCATE_BUFFER bit \n");
	}



	return oldDispatch(deviceObject, Irp);
}





DWORD64		placeDiskHook()
{
	KIRQL   tempirql = disableWP();

	UNICODE_STRING diskDriverName;
	DRIVER_OBJECT* diskDriverObject = NULL;

	RtlInitUnicodeString(&diskDriverName, L"\\Driver\\disk");
	ObReferenceObjectByName(&diskDriverName, OBJ_KERNEL_HANDLE, 0, GENERIC_ALL, *IoDriverObjectType, KernelMode, 0, &diskDriverObject);


	oldDispatch = &spoofDisk;

	if (diskDriverObject)
	{
		SwapPointer(&diskDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], &oldDispatch);
		DbgPrint("device object location of diskdriverobject is: %p \n", diskDriverObject->DeviceObject);
	}

	enableWP(tempirql);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driverObject, PUNICODE_STRING registryPath)
{
	placeDiskHook();
}


NTSTATUS RealDriverEntry(DRIVER_OBJECT* driverObject, PUNICODE_STRING registryPath)
{
	DbgPrint("driver start\n");
	DriverEntry(driverObject, registryPath);
}