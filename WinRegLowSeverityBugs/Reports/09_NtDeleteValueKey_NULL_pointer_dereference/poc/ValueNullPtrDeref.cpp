#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>
#include <winternl.h>

#include <cstdio>

#pragma comment(lib, "ntdll")

extern "C" {

NTSTATUS NTAPI NtDeleteValueKey(
  HANDLE          KeyHandle,
  PUNICODE_STRING ValueName
);

}  // extern "C"

int main() {
  HKEY hTestKey;
  LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER,
                             L"Software",
                             0,
                             KEY_SET_VALUE,
                             &hTestKey);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyExW failed with error %d\n", st);
    return 1;
  }

  UNICODE_STRING ValueName = { 0xccce, 0xccce, NULL };
  NTSTATUS Status = NtDeleteValueKey(hTestKey, &ValueName);

  if (!NT_SUCCESS(Status)) {
    printf("NtDeleteValueKey failed with error %x\n", Status);
    return 1;
  }

  RegCloseKey(hTestKey);

  return 0;
}
