#include <Windows.h>
#include <ktmw32.h>
#include <sddl.h>

#include <cstdio>

#pragma comment(lib, "ktmw32")

int main(int argc, char** argv) {
  LSTATUS st;

  //
  // Create a transaction.
  //

  HANDLE hTrans = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);

  if (hTrans == INVALID_HANDLE_VALUE) {
    printf("CreateTransaction failed with error %u\n", GetLastError());
    return 1;
  }

  //
  // Transactionally create the first instance of the key in HKCU with
  // a permissive security descriptor.
  //

  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = FALSE;

  CONST WCHAR* szSD1 = L"D:(A;;KA;;;WD)"; // Allow KEY_ALL_ACCESS for Everyone.

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          szSD1, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
    printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
           "error %u\n", GetLastError());
    return 1;
  }

  HKEY hTestKey;

  st = RegCreateKeyTransactedW(HKEY_CURRENT_USER,
                               L"TestKey",
                               0,
                               NULL,
                               REG_OPTION_VOLATILE,
                               KEY_ALL_ACCESS,
                               &sa,
                               &hTestKey,
                               NULL,
                               hTrans,
                               NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyTransactedW #1 failed with error %d\n", st);
    return 1;
  }

  RegCloseKey(hTestKey);

  //
  // Transactionally delete the key.
  //

  st = RegDeleteKeyTransactedW(HKEY_CURRENT_USER,
                               L"TestKey",
                               0,
                               0,
                               hTrans,
                               NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegDeleteKeyTransactedW failed with error %d\n", st);
    return 1;
  }

  //
  // Transactionally create the second instance of the key in HKCU with
  // a restrictive security descriptor.
  //

  CONST WCHAR* szSD2 = L"D:(A;;KA;;;BA)"; // Allow KEY_ALL_ACCESS for Administrators.

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          szSD2, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
    printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
           "error %u\n", GetLastError());
    return 1;
  }

  st = RegCreateKeyTransactedW(HKEY_CURRENT_USER,
                               L"TestKey",
                               0,
                               NULL,
                               REG_OPTION_VOLATILE,
                               KEY_ALL_ACCESS,
                               &sa,
                               &hTestKey,
                               NULL,
                               hTrans,
                               NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyTransactedW #2 failed with error %d\n", st);
    return 1;
  }

  //
  // Set a new value in the transactionally created key.
  //

  st = RegSetValueExW(hTestKey,
                      L"Secret",
                      0,
                      REG_SZ,
                      (const BYTE*)L"Secret data",
                      22);

  if (st != ERROR_SUCCESS) {
    printf("RegSetValueExW failed with error %d\n", st);
    return 1;
  }

  //
  // Commit the transaction.
  //

  if (!CommitTransaction(hTrans)) {
    printf("CommitTransaction failed with error %u\n", GetLastError());
    return 1;
  }

  RegCloseKey(hTestKey);
  CloseHandle(hTrans);

  return 0;
}
