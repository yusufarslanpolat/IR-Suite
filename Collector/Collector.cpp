#include <ntifs.h>
#include "CollectorCommon.h"
#include "pch.h"
#include "Proc.h"
#include "Ntstrsafe.h"

// prototypes

void CollectorUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS CollectorCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS CollectorDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
LONG GetProcessList();

fnZwQuerySystemInformation ZwQuerySystemInformation = NULL;
PPROCESS_HEAD_LIST g_processheadlist = NULL;
// DriverEntry

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("Collector DriverEntry started\n"));

	DriverObject->DriverUnload = CollectorUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CollectorCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CollectorCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CollectorDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Collector");
	//RtlInitUnicodeString(&devName, L"\\Device\\ThreadBoost");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Collector");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	KdPrint(("Collector DriverEntry completed successfully\n"));

	return STATUS_SUCCESS;
}

void CollectorUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Collector");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("Collector unloaded\n"));
}

_Use_decl_annotations_
NTSTATUS CollectorCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS CollectorDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	// get our IO_STACK_LOCATION
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PRIORITY_COLLECTOR_GET_EVIDENCE:
	{
		// do the work
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(Config)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto data = (Config*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (data == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Process == TRUE) {
			
			GetProcessList();
			break;
		}

		KdPrint(("ioctl executed."));
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

LONG GetProcessList() {
	KdPrint(("GetProcessList started."));
	LONG st;
	PVOID mem;
	UNICODE_STRING ustr1;
	ULONG bytes = 0;
	PSYSTEM_PROCESS_INFO info = NULL;
	PPROCESS_BUFFER alloc = NULL;
	PPROCESS_BUFFER buffer = NULL;

	RtlSecureZeroMemory(&ustr1, sizeof(ustr1));
	RtlInitUnicodeString(&ustr1, L"ZwQuerySystemInformation");

	ZwQuerySystemInformation = (fnZwQuerySystemInformation)MmGetSystemRoutineAddress(&ustr1);
	if (ZwQuerySystemInformation == NULL)
		return STATUS_UNSUCCESSFUL;

	g_processheadlist = (PPROCESS_HEAD_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_HEAD_LIST), DRIVER_TAG);
	if (g_processheadlist == NULL)
		return LIST_ENTRY_ZERO_MEMORY;

	g_processheadlist->NumberOfProcess = 0;

	st = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bytes);

	if (st == STATUS_INFO_LENGTH_MISMATCH)
	{
		mem = ExAllocatePool(NonPagedPool, bytes);

		if (mem != NULL)
		{
			st = ZwQuerySystemInformation(SystemProcessInformation, mem, bytes, &bytes);

			if (NT_SUCCESS(st))
			{
				info = (PSYSTEM_PROCESS_INFO)mem;

				if (info && MmIsAddressValid(info))
				{

					InitializeListHead(&g_processheadlist->Entry);

					while (info->NextEntryOffset)
					{
						info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);


						buffer = (PPROCESS_BUFFER)ExAllocatePool(NonPagedPool, sizeof(PROCESS_BUFFER));
						RtlSecureZeroMemory(buffer, sizeof(PROCESS_BUFFER));

						buffer->ProcessId = PtrToUlong(info->ProcessId);

						buffer->ProcessInherited = PtrToUlong(info->InheritedFromProcessId);

						buffer->NumberOfThreads = info->NumberOfThreads;

						RtlCopyMemory(buffer->ProcessName, info->ImageName.Buffer, info->ImageName.Length);

						InsertHeadList(&g_processheadlist->Entry, &buffer->Entry);

						g_processheadlist->NumberOfProcess++;

					}
				}
			}
			ExFreePool(mem);
		}
	}

	while (!IsListEmpty(&g_processheadlist->Entry))
	{
		alloc = (PPROCESS_BUFFER)RemoveHeadList(&g_processheadlist->Entry);

		DbgPrint("\n%1ws %20lu %20lu %20lu", alloc->ProcessName, alloc->ProcessId, alloc->ProcessInherited, alloc->NumberOfThreads);

		ExFreePool(alloc);
	}

	ExFreePoolWithTag(g_processheadlist, DRIVER_TAG);

	g_processheadlist = NULL;


	return STATUS_SUCCESS;
}