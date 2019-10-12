// Booster.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include "..\Collector\CollectorCommon.h"


int Error(const char* message) {
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

int main(int argc, const char* argv[]) {
	if (argc < 1) {
		printf("Usage: Collector");
		return 0;
	}

	HANDLE hDevice = CreateFile(L"\\\\.\\Collector", GENERIC_WRITE, FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open device");

	Config data;
	data.Process = TRUE;
	

	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_PRIORITY_COLLECTOR_GET_EVIDENCE, &data, sizeof(data), nullptr, 0, &returned, nullptr);
	if (success)
		printf("Evidence Collected!\n");
	else
		Error("Collecting evidence failed!");

	CloseHandle(hDevice);
}

