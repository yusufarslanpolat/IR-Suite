// Booster.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include "..\Collector\CollectorCommon.h"


int Error(const char* message) {
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

char InputBuffer[100];
int main(int argc, const char* argv[]) {
	//if (argc < 1) {
	//	printf("Usage: Collector");
	//	return 0;
	//}

	auto OutputBuffer = malloc(0x40000);
	if (!OutputBuffer) {
		return 0;
	}
	BOOL bRc;
	ULONG bytesReturned;
	DWORD errNum = 0;
	HANDLE hDevice = CreateFile(L"\\\\.\\Collector", GENERIC_READ | GENERIC_WRITE, 0,
		nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
		return Error("Failed to open device");

	//Config data;
	//data.Process = (PCHAR)"Hello from user mode";
	//char OutputBuffer[0x10000];
	//memset(OutputBuffer, 0, sizeof(OutputBuffer));

	//
		// Printing Input & Output buffer pointers and size
		//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	0x40000);
	//
	// Performing METHOD_BUFFERED
	//

	strcpy_s(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, 0x40000);

	bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_EVIDENCE_COLLECTOR_GET_PROCESSLIST,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		OutputBuffer,
		0x40000,
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl : %d", GetLastError());
		return GetLastError();

	}
	printf("    OutBuffer (%d): %s\n", bytesReturned, (char*)OutputBuffer);


	CloseHandle(hDevice);
	free(OutputBuffer);

}

