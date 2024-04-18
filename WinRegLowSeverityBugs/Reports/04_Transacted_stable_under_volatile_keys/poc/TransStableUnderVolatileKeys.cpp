#include <Windows.h>
#include <ktmw32.h>
#include <sddl.h>

#include <cstdio>

#pragma comment(lib, "advapi32")
#pragma comment(lib, "ktmw32")

int main() {
  //
  // Create a transaction.
  //

  HANDLE hTrans = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);

  if (hTrans == INVALID_HANDLE_VALUE) {
    printf("CreateTransaction failed with error %u\n", GetLastError());
    return 1;
  }

  //
  // Create a transacted volatile parent key in HKCU.
  //

  HKEY hVolatileKey;
  LSTATUS st;

  st = RegCreateKeyTransactedW(HKEY_CURRENT_USER,
                                L"Volatile",
                                0,
                                NULL,
                                REG_OPTION_VOLATILE,
                                KEY_ALL_ACCESS,
                                NULL,
                                &hVolatileKey,
                                NULL,
                                hTrans,
                                NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyTransactedW #1 failed with error %d\n", st);
    return 1;
  }

  //
  // Create the stable subkey.
  //

  HKEY hStableKey;
  st = RegCreateKeyTransactedW(hVolatileKey,
                                L"Stable",
                                0,
                                NULL,
                                0,
                                KEY_ALL_ACCESS,
                                NULL,
                                &hStableKey,
                                NULL,
                                hTrans,
                                NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyTransactedW #2 failed with error %d\n", st);
    return 1;
  }

  //
  // Commit the transaction.
  //

  if (!CommitTransaction(hTrans)) {
    printf("CommitTransaction failed with error %u\n", GetLastError());
    return 1;
  }

  CloseHandle(hTrans);
  RegCloseKey(hStableKey);
  RegCloseKey(hVolatileKey);

  return 0;
}
