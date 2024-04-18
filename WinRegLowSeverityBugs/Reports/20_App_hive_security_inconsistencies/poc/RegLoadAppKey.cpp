#include <Windows.h>

#include <cstdio>

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: %s <hive file>\n", argv[0]);
    return 1;
  }

  HKEY hRootKey;
  LONG st = RegLoadAppKeyA(argv[1], &hRootKey, KEY_ALL_ACCESS, 0, 0);

  if (st != ERROR_SUCCESS) {
    printf("RegLoadAppKeyA failed with error %d\n", st);
    return 1;
  }

  HKEY hSubKey;
  st = RegOpenKeyExW(hRootKey, L"SubKey1", 0, KEY_WRITE, &hSubKey);

  if (st != ERROR_ACCESS_DENIED) {
    printf("RegOpenKeyExW failed with error %d (expected "
           "ERROR_ACCESS_DENIED)\n", st);
    return 1;
  }

  printf("Hive successfully loaded.\n");

  RegCloseKey(hRootKey);

  return 0;
}
