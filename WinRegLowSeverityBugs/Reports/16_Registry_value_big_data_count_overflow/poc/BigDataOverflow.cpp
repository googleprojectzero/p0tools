#include <Windows.h>

#include <cstdio>

int main() {
  CONST DWORD kValueLength = 65536 * 16344;
  LSTATUS st;

  //
  // Allocate and fill the value buffer.
  //

  LPBYTE lpData = (LPBYTE)malloc(kValueLength);

  if (lpData == NULL) {
    printf("Failed to allocate %u bytes\n", kValueLength);
    return 1;
  }

  memset(lpData, 'A', kValueLength);

  printf("Value length to be written: %u\n", kValueLength);
  printf("Value data to be written:   ");

  for (DWORD i = 0; i < 16; i++) {
    printf("%.2x ", lpData[i]);
  }

  printf("\n");

  //
  // Set the value in registry.
  //
  
  st = RegSetValueExW(HKEY_CURRENT_USER,
                      L"TestValue",
                      0,
                      REG_BINARY,
                      lpData,
                      kValueLength);

  if (st != ERROR_SUCCESS) {
    printf("RegSetValueExW failed with error %d\n", st);
    free(lpData);
    return 1;
  }

  //
  // Read the value back from registry.
  //

  DWORD cbData = kValueLength;

  st = RegQueryValueExW(HKEY_CURRENT_USER,
                        L"TestValue",
                        0,
                        NULL,
                        lpData,
                        &cbData);

  if (st != ERROR_SUCCESS) {
    printf("RegQueryValueExW failed with error %d\n", st);
    free(lpData);
    return 1;
  }

  printf("Value length read:          %u\n", cbData);
  printf("Value data read:            ");

  for (DWORD i = 0; i < 16 && i < cbData; i++) {
    printf("%.2x ", lpData[i]);
  }

  printf("\n");

  free(lpData);

  return 0;
}
