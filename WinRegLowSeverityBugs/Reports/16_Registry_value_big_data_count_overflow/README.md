# Windows Kernel integer overflow of big data chunk count when handling very long registry values

The maximum length of registry values in Windows has changed over the course of time. In the original hive version 1.3, it was limited to 1 MiB, which is equivalent to the maximum size of a single cell in a hive. But starting with version 1.4 (introduced in Windows XP), support for longer values was added with the help of a new construct called "big data". When it is used, the `_CM_KEY_VALUE.Data` cell index doesn't point directly to a cell storing the raw data, but instead points to a `_CM_BIG_DATA` structure with the following layout:

```
kd> dt _CM_BIG_DATA
nt!_CM_BIG_DATA
   +0x000 Signature        : Uint2B
   +0x002 Count            : Uint2B
   +0x004 List             : Uint4B
```

The way this mechanism works is that the entire long value is split into smaller chunks of 16344 bytes each (with the exception of the last chunk which can be shorter). The `_CM_BIG_DATA.Count` member specifies the number of chunks making up the value, and the `_CM_BIG_DATA.List` index points to a linear list of these chunks. In this scenario, there is no fixed limit on the length of the value, but it is instead dictated by other restrictions of the Windows registry. For example, one natural upper bound is around ~2 GiB, which is the maximum size of stable/volatile storage spaces in a single hive. Another, even stronger bound is related to the big data structure itself: we may have 65535 (the max value of the 16-bit `_CM_BIG_DATA.Count` field) chunks each containing 16344 bytes, which equals to 1071104040 (0x3FD7C028) bytes that can be stored in such a data structure, or a little less than 1 GiB.

The problem discussed in this report is the fact that the `NtSetValueKey` system call allows the caller to set values longer than 1071104040 bytes. Because of this, any value with a length between 1071104041 (0x3FD7C029) and 2147479552 (0x7FFFF000) will cause a 16-bit integer overflow in the following calculation, performed by `CmpSetValueDataNew` and `CmpSetValueDataExisting`:

```c
_CM_BIG_DATA.Count = (ValueDataLength + 16343) / 16344;
```

For example, if we create a value consisting of 1071120384 (0x3FD80000) bytes, the above formula will evaluate to 0x0 when cast to the `USHORT` type of the `Count` field. This generates an inconsistent state of the hive where the value length is theoretically around 1 GiB (`_CM_KEY_VALUE.DataLength == 0x3FD80000`), but its backing buffer is effectively empty. By choosing lengths between 1 GiB to 2 GiB, an attacker can set `_CM_BIG_DATA.Count` to an arbitrary value inconsistent with `_CM_KEY_VALUE.DataLength`, but setting it to zero seems the most interesting from a security perspective, as this is a state that may never arise organically and therefore could be unexpected/mishandled by other parts of the kernel. However, after a brief investigation, we haven't been able to identify any way to exploit this state for memory corruption or information disclosure. The two outcomes of this behavior that we confirmed are possible are as follows:

- When the overly long value is queried with an API such as `RegQueryValueExW`, it reports the large length via the output `lpcbData` parameter, but fills the output buffer with zeros instead of the original data that was passed in via `RegSetValueExW`. This is because the internal kernel buffer is allocated in `CmpGetValueData` based on `_CM_KEY_VALUE.DataLength`, but filled based on `_CM_BIG_DATA.Count`. In theory this could lead to information disclosure as a partially initialized kernel buffer is returned to user-mode, but in practice, as far as we know, `ExAllocatePoolWithTag` always returns zero'ed out memory for allocation sizes in the order of gigabytes, so no interesting data would ever get leaked.

- When a hive containing an overly long value is unloaded and loaded again (e.g. HKCU after a sign-out/sign-in sequence), the loader detects the inconsistency between `_CM_KEY_VALUE.DataLength` and `_CM_BIG_DATA.Count` and forcibly removes the value from the key. This makes such a value volatile in nature even though it is stored in a stable key.

Attached is a proof-of-concept program that performs the following steps:

1. Creates a value with data length equal to 1071120384 filled with the letter 'A' under HKCU.
2. Queries the value and prints out its supposed length and the initial 16 bytes. On an affected system, this should show a reported length of 1071120384 but the value bytes being equal to 0x00 instead of the expected 0x41.

The issue has been successfully reproduced on Windows 11 22H2 (January 2024 update, build 22621.3007) running in a VM with 8 GB of RAM.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.