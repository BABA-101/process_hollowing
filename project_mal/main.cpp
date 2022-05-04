#include <stdio.h>
#include <Windows.h>

int main(int argc, const char* argv[]) {

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	char szCommandLine[] = TEXT("NOTEPAD");

	if (!CreateProcess(NULL, szCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("CreateProcess false... %d \n", GetLastError());
		return 1;
	}
}