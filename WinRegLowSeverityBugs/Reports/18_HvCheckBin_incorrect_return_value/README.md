# Windows Kernel returns success in an error path of HvCheckBin during registry hive sanitization

The `HvCheckBin` kernel function is responsible for validating the structural correctness of each "bin" found in a registry hive being currently loaded in Windows. On the low level, bins consist of a header and consecutive chunks of data called "cells", so the job of `HvCheckBin` is to make sure that all cells reside within the bounds of the bin, and that they fill the full bin space. Historically, the function used to return an integer: zero in case of success and non-zero in case of failure. The meaning of the specific error codes can be looked up by analyzing old debug/checked builds of the kernel, which contain some useful debug strings:

- `"HvCheckBin 1000: last cell points off the end\n"`
- `"HvCheckBin 995: sizes do not add up\n"`
- `"HvCheckBin 40: impossible allocation\n"`
- `"HvCheckBin 50: allocated exceeds available\n"`
- `"HvCheckBin 70: free exceeds available\n"`
- `"HvCheckBin 60: impossible free block\n"`

According to our analysis, some time around the release of Windows 10 1703 in 2017, this code was refactored to start using the unified `NTSTATUS` return type, and the values of 40, 50 etc. were converted to a single generic `STATUS_REGISTRY_CORRUPT` (0xC000014C) error code. The caller of `HvCheckBin` - `HvCheckHive` - was also updated to respect the semantics of the `NTSTATUS` type, where zero or positive 32-bit integers indicate success, and negative 32-bit numbers indicate failure.

The problem is that the refactoring must have missed one return statement, and so there is still a place in the function which returns the value of 60 when it wants to signal the "impossible free block" error. But when used as an `NTSTATUS`, it is treated as a success and allows the hive loading to continue. In theory, this should make it possible to load a corrupted hive with an invalid free block, potentially leading to memory corruption and enabling local privilege escalation. However, when we tried to reproduce it, we couldn't reach the affected code because of another level of hive sanitization occurring earlier in the process. Specifically, there is a `HvpEnlistFreeCells` function which also iterates through the cells of a bin in order to enlist them in internal structures, and if it detects any inconsistencies, it "fixes" the problematic cell by overwriting it with a free region spanning until the end of the bin. The routine is reached through the following sequence of calls:

```
#00 nt!HvpEnlistFreeCells
#01 nt!HvpRemapAndEnlistHiveBins
#02 nt!HvLoadHive
#03 nt!HvHiveStartFileBacked
#04 nt!CmpCreateHive
#05 nt!CmpInitHiveFromFile
#06 nt!CmpCmdHiveOpen
#07 nt!CmLoadAppKey
#08 nt!CmLoadDifferencingKey
#09 nt!NtLoadKeyEx
```

Consequently, when execution later enters `HvCheckBin`, the bin appears to always be in a valid state, which effectively mitigates the issue. Since we haven't found any practical ways to exploit the bug, we are uncertain if it has any security impact, but we are submitting it for additional assessment to MSRC. We have verified this behavior on Windows 11 22H2 (January 2024 update, build 10.0.22621.3007) but believe it likely applies to all versions of Windows following the refactoring.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.