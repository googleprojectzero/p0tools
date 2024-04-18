#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>

#include <cstdio>

#pragma comment(lib, "ntdll.lib")

extern "C" {

NTSTATUS NTAPI NtCreateRegistryTransaction(PHANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD);
NTSTATUS NTAPI NtRollbackRegistryTransaction(HANDLE, DWORD);

}  // extern "C"

int main() {
  LSTATUS st;

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
  // Open HKCU\Software in the scope of a transaction.
  //

  HKEY hTransactedKey;

  st = RegOpenKeyTransactedW(HKEY_CURRENT_USER,
                             L"Software",
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
  // Roll back the transaction, changing its state to non-active.
  //

  Status = NtRollbackRegistryTransaction(hTrans, 0);

  if (!NT_SUCCESS(Status)) {
    printf("NtRollbackRegistryTransaction failed with error %.8x\n", Status);
    return 1;
  }

  //
  // Try to perform some operation on the transacted key, which should fail,
  // but will also leak a reference to the transaction.
  //

  st = RegSetValueExW(hTransactedKey,
                      L"Test",
                      0,
                      REG_BINARY,
                      (const BYTE*)"AAAA",
                      4);

  if (st != ERROR_TRANSACTION_NOT_ACTIVE) {
    printf("RegSetValueExW failed with error %d "
           "(expected ERROR_TRANSACTION_NOT_ACTIVE)\n", st);
    return 1;
  }

  //
  // Cleanup.
  //

  RegCloseKey(hTransactedKey);
  CloseHandle(hTrans);

  return 0;
}
