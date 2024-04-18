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
  // Open an existing key in HKCU within the transaction.
  //

  HKEY hTestKey;
  st = RegOpenKeyTransactedW(HKEY_CURRENT_USER,
                             L"Software",
                             0,
                             KEY_SET_VALUE,
                             &hTestKey,
                             hTrans,
                             NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyTransactedW failed with error %d\n", st);
    return 1;
  }

  //
  // Set a new value in the transactionally opened key.
  //

  st = RegSetValueExW(hTestKey,
                      L"Value",
                      0,
                      REG_BINARY,
                      (const BYTE*)"AAAA",
                      4);

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
