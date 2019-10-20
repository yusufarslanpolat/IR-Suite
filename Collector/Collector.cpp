#include <ntifs.h>
#include "CollectorCommon.h"
#include "pch.h"
#include "Proc.h"
#include "Ntstrsafe.h"

// prototypes

extern "C" {
	NTSTATUS
		DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
	void CollectorUnload(_In_ PDRIVER_OBJECT DriverObject);
	NTSTATUS CollectorCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
	NTSTATUS CollectorDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
	LONG GetProcessList();
	VOID
		PrintIrpInfo(
			PIRP Irp
		);
	VOID
		PrintChars(
			_In_reads_(CountChars) PCHAR BufferAddress,
			_In_ size_t CountChars
		);

	fnZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	PPROCESS_HEAD_LIST g_processheadlist = NULL;
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, CollectorUnload)
#pragma alloc_text( PAGE, CollectorDeviceControl)
#pragma alloc_text( PAGE, GetProcessList)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA
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
		PAGED_CODE();
		UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Collector");
		// delete symbolic link
		IoDeleteSymbolicLink(&symLink);

		// delete device object
		IoDeleteDevice(DriverObject->DeviceObject);

		KdPrint(("Collector unloaded\n"));
	}

	_Use_decl_annotations_
		NTSTATUS CollectorCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
		PAGED_CODE();
		UNREFERENCED_PARAMETER(DeviceObject);

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	_Use_decl_annotations_
		NTSTATUS CollectorDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
		PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
		NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
		ULONG               inBufLength; // Input buffer length
		ULONG               outBufLength; // Output buffer length
		PCHAR               inBuf, outBuf; // pointer to Input and output buffer
		PCHAR               data = "This String is from Device Driver !!!";
		size_t              datalen = strlen(data) + 1;//Length of data including null
		PAGED_CODE();

		irpSp = IoGetCurrentIrpStackLocation(Irp);
		inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (!inBufLength || !outBufLength)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			goto End;
		}

		//
		// Determine which I/O control code was specified.
		//

		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_EVIDENCE_COLLECTOR_GET_PROCESSLIST:

			//
			// In this method the I/O manager allocates a buffer large enough to
			// to accommodate larger of the user input buffer and output buffer,
			// assigns the address to Irp->AssociatedIrp.SystemBuffer, and
			// copies the content of the user input buffer into this SystemBuffer
			//

			DbgPrint("Called IOCTL_SIOCTL_METHOD_BUFFERED\n");
			PrintIrpInfo(Irp);

			//
			// Input buffer and output buffer is same in this case, read the
			// content of the buffer before writing to it
			//

			inBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
			outBuf = (PCHAR)Irp->AssociatedIrp.SystemBuffer;

			//
			// Read the data from the buffer
			//

			DbgPrint("\tData from User :");
			//
			// We are using the following function to print characters instead
			// DebugPrint with %s format because we string we get may or
			// may not be null terminated.
			//
			PrintChars(inBuf, inBufLength);

			//
			// Write to the buffer over-writes the input buffer content
			//

			RtlCopyBytes(outBuf, data, outBufLength);

			DbgPrint("\tData to User : ");
			PrintChars(outBuf, datalen);
			GetProcessList();
			//
			// Assign the length of the data copied to IoStatus.Information
			// of the Irp and complete the Irp.
			//

			Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

			//
			// When the Irp is completed the content of the SystemBuffer
			// is copied to the User output buffer and the SystemBuffer is
			// is freed.
			//
			break;
		default:

			//
			// The specified I/O control code is unrecognized by this driver.
			//

			ntStatus = STATUS_INVALID_DEVICE_REQUEST;
			DbgPrint("ERROR: unrecognized IOCTL %x\n",
				irpSp->Parameters.DeviceIoControl.IoControlCode);
			break;
		}

	End:
		//
		// Finish the I/O operation by simply completing the packet and returning
		// the same status as in the packet itself.
		//

		Irp->IoStatus.Status = ntStatus;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return ntStatus;
	}

	LONG GetProcessList() {
		PAGED_CODE();
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

	VOID
		PrintIrpInfo(
			PIRP Irp)
	{
		PIO_STACK_LOCATION  irpSp;
		irpSp = IoGetCurrentIrpStackLocation(Irp);

		PAGED_CODE();

		DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
			Irp->AssociatedIrp.SystemBuffer);
		DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
		DbgPrint("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
			irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
		DbgPrint("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
			irpSp->Parameters.DeviceIoControl.InputBufferLength);
		DbgPrint("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
			irpSp->Parameters.DeviceIoControl.OutputBufferLength);
		return;
	}

	VOID
		PrintChars(
			_In_reads_(CountChars) PCHAR BufferAddress,
			_In_ size_t CountChars
		)
	{
		PAGED_CODE();

		if (CountChars) {

			while (CountChars--) {

				if (*BufferAddress > 31
					&& *BufferAddress != 127) {

					DbgPrint("%c", *BufferAddress);

				}
				else {

					DbgPrint(".");

				}
				BufferAddress++;
			}
			DbgPrint("\n");
		}
		return;
	}
}