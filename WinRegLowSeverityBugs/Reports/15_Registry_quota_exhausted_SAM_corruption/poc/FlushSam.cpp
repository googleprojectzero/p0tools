#include <Windows.h>

#include <cstdio>

int main() {
  HKEY hSam;

  //
  // Open a handle to HKLM\SAM with read access.
  //

  LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hSam);

  if (st != ERROR_SUCCESS) {
    printf("RegOpenKeyExW failed with error %d\n", st);
    return 1;
  }

  //
  // Flush the hive.
  //

  st = RegFlushKey(hSam);

  if (st != ERROR_SUCCESS) {
    printf("RegFlushKey failed with error %d\n", st);
    return 1;
  }

  //
  // Cleanup.
  //

  RegCloseKey(hSam);

  return 0;
}
