#include "pch.h"
#include "CollectorCommon.h"
#include "Driver.h"
#include "Proc.h"
PRTL_PROCESS_MODULES QueryModuleInformation()
{
	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES system_information = NULL;
	UNREFERENCED_PARAMETER(system_information);
	ULONG retlen = 0;

	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return NULL;
	}
	ULONG bufsize = retlen + 10 * sizeof(RTL_PROCESS_MODULE_INFORMATION);
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bufsize);
	if (modules == NULL) {
		return NULL;
	}
	UNICODE_STRING ustr1;
	RtlSecureZeroMemory(&ustr1, sizeof(ustr1));
	RtlInitUnicodeString(&ustr1, L"ZwQuerySystemInformation");

	ZwQuerySystemInformation = (fnZwQuerySystemInformation)MmGetSystemRoutineAddress(&ustr1);
	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bufsize, &retlen);
	if (!NT_SUCCESS(status)) {
		ExFreePool(modules);
		return NULL;
	}

	return modules;
}

NTSTATUS DriverEnumInfo(PVOID	inbuf, ULONG inlen, PVOID outbuf, ULONG outlen, PIRP irp)
{
	DbgPrint("driverenuminfo");
	UNREFERENCED_PARAMETER(inlen);
	UNREFERENCED_PARAMETER(inbuf);
	PRTL_PROCESS_MODULES mods = QueryModuleInformation();
	if (!mods) {
		return STATUS_UNSUCCESSFUL;
	}
	ULONG count = mods->NumberOfModules;
	ULONG size = count * sizeof(DRIVER_ITEM) + 4;
	if (size > outlen) {
		irp->IoStatus.Information = size + 10 * sizeof(DRIVER_ITEM);
		ExFreePool(mods);
		return STATUS_BUFFER_OVERFLOW;
	}
	PDRIVER_INFO info = (PDRIVER_INFO)outbuf;
	info->count = count;
	for (ULONG i = 0; i < count; i++) {
		auto &item = info->items[i];
		auto &mod = mods->Modules[i];
#ifdef _AMD64_
		item.base = (ULONG64)mod.ImageBase;
#else
		item.base = (ULONG64)(ULONG)mod.ImageBase;
#endif
		item.size = mod.ImageSize;
		item.flags = mod.Flags;
		item.init_seq = mod.InitOrderIndex;
		item.load_seq = mod.LoadOrderIndex;
		DbgPrint("full path %s",mod.FullPathName);
		RtlCopyMemory(item.path, mod.FullPathName, sizeof(mod.FullPathName));
	}
	ExFreePool(mods);
	irp->IoStatus.Information = size;
	return STATUS_SUCCESS;
}
NTSTATUS DriverDispatcher(IN ULONG op, IN PIRP irp)
{
	//KdBreakPoint();

	NTSTATUS status;
	PIO_STACK_LOCATION	irpstack;
	PVOID	inbuf = NULL;
	PVOID outbuf = NULL;
	ULONG inlen = 0;
	ULONG outlen = 0;
	irpstack = IoGetCurrentIrpStackLocation(irp);
	inbuf = (UCHAR*)irp->AssociatedIrp.SystemBuffer + 4;
	inlen = irpstack->Parameters.DeviceIoControl.InputBufferLength - 4;
	outbuf = irp->AssociatedIrp.SystemBuffer;
	outlen = irpstack->Parameters.DeviceIoControl.OutputBufferLength;
	status = STATUS_SUCCESS;
	DbgPrint("inside of IOCTL_EVIDENCE_COLLECTOR_GET_DRIVERLIST");
	switch (op) {
	case DRIVER_ENUM_INFO:
		DbgPrint("inside of DRIVER_ENUM_INFO");
		status = DriverEnumInfo(inbuf, inlen, outbuf, outlen, irp);
		break;
	default:
		break;
	}
	return status;
}