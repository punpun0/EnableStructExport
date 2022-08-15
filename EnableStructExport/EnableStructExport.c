#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <psapi.h>
#include <wchar.h>
#include <string.h>
#include <TlHelp32.h>

static uint8_t memory[0x5000000];
#define STRUCT_EXPORT_ENABLED_SIGNATURE (0x5F74726F70786523)

uintptr_t GetProcessBaseAddress(HANDLE process)
{
	DWORD_PTR   baseAddress = 0;
	HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, process);
	HMODULE* moduleArray;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;

	if (processHandle)
	{
		/* retrieves bytes required for storing all handles */
		if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				/* LPTR Allocates fixed memory. The return value is a pointer to the memory object. Initializes memory contents to zero. */
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (uintptr_t*)moduleArrayBytes;

					/* Retrieves a handle for each module in the specified process. */
					if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
					{
						baseAddress = moduleArray[0];
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}

		CloseHandle(processHandle);
	}

	return baseAddress;
}

DWORD GetProcId(WCHAR* name)
{
	/* tlhelp32.h is used for this*/
	/* creates and entry point */
	PROCESSENTRY32 entry;
	/* dwsize must be set to sizeof(PROCESSENTRY32), otherwise fails, as mentioned in the documentation */
	entry.dwSize = sizeof(PROCESSENTRY32);

	/* creates snapshot of memory */

	/* multiple flags (modes) of creating snapshot
	* TH32CS_SNAPPROCESS
	* Includes all processes in the system in the snapshot. To enumerate the processes, see Process32First.
	* Process ID is NULL (unknown)
	*/
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);


	/*
	* Process32First
	* Retrieves information about the first process encountered in a system snapshot.
	*/

	/*
	* Returns TRUE if the first entry of the process list has been copied to the buffer or FALSE otherwise.
	*/
	if (Process32First(snapshot, &entry) == TRUE)
	{
		/*
		* Process32Next
		* Retrieves information about the next process recorded in a system snapshot.
		*/

		/* So this loops until it find the process we need */
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			/* compares WCHAR type string*/
			/* im assuming the entry gets updated everytime the Process32First or the Process32Next function is called */
			if (wcscmp(entry.szExeFile, name) == 0)
			{
				/* if match, return the process id */
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return NULL;
}

void writeToMem(HANDLE hProcess, uint64_t magic_addr) {
	DWORD permissions;

	uint64_t cur_exp_enabled = -1;
	uint64_t exp_enabled_new = 0;
	/* get permissions for writing memory */
	VirtualProtectEx(hProcess, (void*)magic_addr, sizeof(uint64_t), PAGE_EXECUTE_READWRITE, &permissions);

	while (cur_exp_enabled != 0) {
		BOOL success = ReadProcessMemory(hProcess, (void*)magic_addr, &cur_exp_enabled, sizeof(uint64_t), 0);
		if (!success)
			continue;
		if (cur_exp_enabled == STRUCT_EXPORT_ENABLED_SIGNATURE) {
			/* write 0 to the location of the memory */
			success = WriteProcessMemory(hProcess, (void*)magic_addr, &exp_enabled_new, sizeof(uint64_t), 0);
			if (!success)
				continue;
			success = ReadProcessMemory(hProcess, (void*)magic_addr, &cur_exp_enabled, sizeof(uint64_t), 0);
			if (!success)
				continue;
		}
	}
	/* restore permissions */
	VirtualProtectEx(hProcess, (void*)magic_addr, sizeof(uint64_t), permissions, &permissions);

	printf("Patched: %llx\n", magic_addr);
	return;
}


void SearchMemory(HANDLE hProcess, uintptr_t startAddress, uint64_t find) {
	uint64_t* mem_ptr;
	uintptr_t mem_start = &memory[0];
	mem_ptr = mem_start;

	/* reads (writes) bytes into the memory array */
	ReadProcessMemory(hProcess, (void*)startAddress, &memory, sizeof(memory), 0);

	uintptr_t final_mem;

	for (int i = 0; i < 0x5000000; i++) {
		/* find addresses with matching signature */
		if (*mem_ptr == find) {
			final_mem = (startAddress + ((uintptr_t)mem_ptr - mem_start));
			printf("Found at: %llx\n", final_mem);
			writeToMem(hProcess, final_mem);
		}
		((uint8_t*)mem_ptr)++;
	}

	return;
}


int main(int argc, char* argv[])
{
	/* fills memory array with 0 */
	memset(memory, 0, sizeof(memory));

	/* get's the process ID of the exe */
	DWORD proc_id = NULL;

	printf("Please open Minecraft Bedrock\n");
	while (proc_id == NULL)
	{
		proc_id = GetProcId(L"Minecraft.Windows.exe");
		if (proc_id == NULL)
			/* different name of the exe, if running with dx11 */
			proc_id = GetProcId(L"Minecraft.Win10.DX11.exe");
	}


	printf("MC Process ID: 0x%x\n", proc_id);
	/* https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights */
	/* TRUE inherits the handle(hProccess) */
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, proc_id);
	printf("MC Process Handle: 0x%lx\n", hProcess);

	if (!hProcess)
	{
		MessageBox(NULL, L"Cannot open process!\r\nTry \"Run as administrator\"", L"Error!", MB_OK + MB_ICONERROR);
	}
	else
	{

		uintptr_t baseAddress = NULL;
		while (baseAddress == NULL)
			baseAddress = GetProcessBaseAddress(proc_id);

		printf("MC Base Addr: 0x%llx\n", baseAddress);

		printf("Searching for \"#export_enabled\"...\n");

		SearchMemory(hProcess, baseAddress, STRUCT_EXPORT_ENABLED_SIGNATURE);

		printf("Done patching!\n");

		CloseHandle(hProcess);

		return 0;
	}
}

