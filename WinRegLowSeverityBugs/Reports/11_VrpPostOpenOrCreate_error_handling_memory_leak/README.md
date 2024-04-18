# Windows Kernel memory leak in VrpPostOpenOrCreate when propagating error conditions

In the October 2023 Patch Tuesday, Microsoft addressed several problems related to the handling of differencing hives and layered keys, in response to Project Zero issue #2466 (MSRC-80825 / CVE-2023-36576). One change was introduced in the `VrpPostOpenOrCreate` function to fix the findings described in the "Container escapes through out-of-memory conditions" section, by adding a short snippet of code at the end of the routine looking something like the following:

```c
if (!NT_SUCCESS(Status)) {
  PostOperationInfo->ReturnStatus = Status;
  return STATUS_CALLBACK_BYPASS;
}
```

The purpose of this code is to propagate any potential errors back to `VrpRegistryCallback` and further up the callstack. It does indeed do its job of blocking registry container escapes; however, it doesn't fully follow the advice found in the [Handling Notifications](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-notifications) MSDN article:

```
If the driver changes a status code from success to failure, it might have to deallocate objects that the configuration manager allocated.
```

This is directly applicable to the code in question: in the error path, `VrpPostOpenOrCreate` changes the status code from success to failure. As opening the key has already succeeded prior to the callback, a corresponding key body object has been allocated in `CmpCreateKeyBody` and is pointed to by the `REG_POST_OPERATION_INFORMATION.Object` member; however it is never freed by `VrpPostOpenOrCreate`. Instead, the reference to the new key body is quietly dropped, which leads to a memory leak of both the key body and its associated key control block. The original proof-of-concept exploit `VrpBuildKeyPath_poc.cpp` from issue #2466 reproduces this behavior when launched inside a Docker container - it has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715).

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.