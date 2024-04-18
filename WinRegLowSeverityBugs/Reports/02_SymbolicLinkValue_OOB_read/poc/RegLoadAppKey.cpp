#include <Windows.h>

#include <cstdio>

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: %s <hive file>\n", argv[0]);
    return 1;
  }

  HKEY hkey;
  LONG st = RegLoadAppKeyA(argv[1], &hkey, KEY_ALL_ACCESS, 0, 0);
  if (st != ERROR_SUCCESS) {
    printf("RegLoadAppKeyA failed with error %d\n", st);
  } else {
    printf("Hive successfully loaded\n");
    RegCloseKey(hkey);
  }

  return 0;
}
