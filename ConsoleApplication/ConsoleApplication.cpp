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
	//data.Process = TRUE;
	char OutputBuffer[0x10000];
	memset(OutputBuffer, 0, sizeof(OutputBuffer));

	DWORD returned;
	BOOL success = DeviceIoControl(hDevice, IOCTL_EVIDENCE_COLLECTOR_GET_PROCESSLIST, &data, sizeof(data), &OutputBuffer, sizeof(OutputBuffer), &returned, nullptr);
	if (success) {
		printf("Evidence Collected!\n");
		printf("OutBuffer (%d): %s\n", returned, OutputBuffer);
	}
	else
		Error("Collecting evidence failed!");

	CloseHandle(hDevice);
}

