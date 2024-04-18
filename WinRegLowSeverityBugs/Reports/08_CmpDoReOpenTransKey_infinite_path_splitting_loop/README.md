# Windows Kernel infinite loop in CmpDoReOpenTransKey when recovering a corrupted transaction log

In the April 2023 Patch Tuesday, an official fix was shipped by Microsoft to address Project Zero issue #2419 (CVE-2023-28272, CVE-2023-28293). The original issue was insufficient sanitization of the KTM transaction log files, and a resulting out-of-bounds read access in `CmpDoReDoCreateKey`/`CmpDoReOpenTransKey` when processing invalid registry paths that were either empty or didn't contain any backslashes. Since local attackers may plant such transaction log files next to registry hives which get loaded by the system (e.g. NTUSER.DAT/NTUSER.MAN in %USERPROFILE%), they do have full binary control over such files and may reach the recovery code with arbitrary data, making it a valid attack surface.

As part of April's fix, a new internal `CmpSplitParentKeyName` kernel function was introduced to safely split a given registry path into the "base" and "leaf" parts, i.e. split it into two strings at the last backslash (if it exists). But at the same time, a new problem was introduced in how the routine is used by `CmpDoReOpenTransKey`. Let's demonstrate it with the following pseudo-code:

```c
NTSTATUS CmpDoReOpenTransKey(PUNICODE_STRING KeyPath) {
  UNICODE_STRING BasePath = *KeyPath;
  UNICODE_STRING LeafKey;

  while (1) {
    NTSTATUS Status = ObOpenObjectByName(BasePath);
    
    if (NT_SUCCESS(Status)) {
      break;
    }

    CmpSplitParentKeyName(KeyPath, &BasePath, &LeafKey);

    if (BasePath.Length == 0) {
      return Status;
    }
  }

  //
  // Rest of the function body.
  //
}
```

Here, the input `KeyPath` argument is a potentially user-controlled string. The presumed intent of the code is to remove the last component from the path one by one, until a base path that exists in the registry tree is found. But let's note that the first argument to `CmpSplitParentKeyName` is always `KeyPath`, the full input path and not the partially stripped one from the previous iteration of the loop. This means that if the loop doesn't complete within a single iteration, it will keep spinning indefinitely and never reach the exit condition. For example, if a log file specifies a registry operation on the path `HKCU\A\B` where neither `HKCU\A\B` or `HKCU\A` exist, then `CmpSplitParentKeyName` will indefinitely keep splitting `"HKCU\A\B"` into `["HKCU\A", "B"]` while never being able to open `HKCU\A`. This may be abused for a local denial-of-service attack by completely locking one CPU core inside the `CmpDoReOpenTransKey` function.

For this issue, we haven't prepared an end-to-end proof of concept exploit, but instead used a combination of a user-mode program and WinDbg kernel debugging to generate a transaction log file that triggers the bug. The attached simple `CreateTransactionLog` program transactionally opens the `HKCU\Software` key and adds a new value within it. To reproduce the issue, we follow these steps:

1. Attach to the test system with WinDbg as a kernel debugger.
2. Break into the debugger with CTRL+BREAK or similar.
3. Set a breakpoint on the `HvBufferCheckSum` function: `kd> bp nt!HvBufferCheckSum`
4. Set a breakpoint on the `CmpTransMgrCommit` function: `kd> bp nt!CmpTransMgrCommit`
5. Resume system execution: `kd> g`
6. Start the `CreateTransactionLog` program in the test system.
7. The breakpoint for `HvBufferCheckSum` is hit and we break into the debugger.
8. Modify the serialized log record located under the RCX register (first argument of `HvBufferCheckSum`) to change the referenced key path to one where at least two of the last components don't exist. In our case, we replaced `\REGISTRY\USER\<SID>\Software` with `\REGISTRY\USER\<SID>\AAAA\BBB` with the following command: `kd> eu @rcx+50 "\\REGISTRY\\USER\\S-1-5-21-123456789-123456789-1234567890-1234\\AAAA\\BBB"`
9. Resume system execution: `kd> g`
10. The breakpoint for `HvBufferCheckSum` is hit again. Resume: `kd> g`
11. The breakpoint for `CmpTransMgrCommit` is hit. Reboot the system: `kd> .reboot`

At this point, the transaction log files for the user's hive should contain the specially crafted record that triggers the bug. We used a breakpoint on `HvBufferCheckSum` in order to modify the serialized record after it is initialized, but just before the final checksum is calculated and before it is written to disk. The first breakpoint being hit corresponds to the "SetValue" record. Then, we break on `CmpTransMgrCommit` and reboot to make sure that the transaction has been marked as "Prepared" but not "Committed" yet, which will trigger the transaction recovery code in `CmpDoReOpenTransKey` that we are targeting.

After the system reboots and we try to sign in as the same user, we shouldn't be able to, as the `NtLoadKey3` system call that was supposed to load the user hive keeps spinning endlessly in `CmpDoReOpenTransKey`. We can break into the debugger by pressing CTRL+BREAK and examine the stack trace ourselves:

```
kd> k
 # Child-SP          RetAddr               Call Site
00 fffff801`69591b48 fffff801`71ad31a5     nt!DbgBreakPointWithStatus
01 fffff801`69591b50 fffff801`71ad3070     kdnic!TXTransmitQueuedSends+0x125
02 fffff801`69591b90 fffff801`6aa7610b     kdnic!TXSendCompleteDpc+0x180
03 fffff801`69591bd0 fffff801`6aa73cf4     nt!KiProcessExpiredTimerList+0x1eb
04 fffff801`69591d00 fffff801`6ac1fdf5     nt!KiRetireDpcList+0xaf4
05 fffff801`69591fb0 fffff801`6ac1fd9f     nt!KxSwapStacksAndRetireDpcList+0x5
06 ffffe203`7fac1f80 fffff801`6aa61645     nt!KiPlatformSwapStacksAndCallReturn
07 ffffe203`7fac1f90 fffff801`6ac1f56b     nt!KiDispatchInterrupt+0xd5
08 ffffe203`7fac2080 fffff801`6ac193c1     nt!KiDpcInterruptBypass+0x1b
09 ffffe203`7fac20b0 fffff801`6aaed039     nt!KiInterruptDispatchNoLockNoEtw+0xb1
0a ffffe203`7fac2240 fffff801`6aaecf2f     nt!PsBoostThreadIoEx+0xf9
0b ffffe203`7fac22a0 fffff801`6b2f3573     nt!PsBoostThreadIo+0xf
0c ffffe203`7fac22d0 fffff801`6af4892a     nt!CmpUnlockRegistry+0x33
0d ffffe203`7fac2300 fffff801`6af42b35     nt!CmpDoParseKey+0x395a
0e ffffe203`7fac2750 fffff801`6aef2884     nt!CmpParseKey+0x2e5
0f ffffe203`7fac2940 fffff801`6aef1232     nt!ObpLookupObjectName+0x1104
10 ffffe203`7fac2ad0 fffff801`6ae8a7ea     nt!ObOpenObjectByNameEx+0x1f2
11 ffffe203`7fac2c00 fffff801`6b228ad2     nt!ObOpenObjectByName+0x5a
12 ffffe203`7fac2c50 fffff801`6b22895f     nt!CmpDoReOpenTransKey+0x126
13 ffffe203`7fac2e90 fffff801`6b228740     nt!CmpDoReDoSetValueExisting+0x27
14 ffffe203`7fac2ed0 fffff801`6b21cdfe     nt!CmpDoReDoRecord+0x84
15 ffffe203`7fac2f00 fffff801`6b12cb49     nt!CmpRmReDoPhase+0x142
16 ffffe203`7fac2fc0 fffff801`6af87e46     nt!CmpStartRMLog+0xc5271
17 ffffe203`7fac30e0 fffff801`6aaf310e     nt!CmpInitCmRM+0x6ae
18 ffffe203`7fac32c0 fffff801`6afe0dbd     nt!CmpLoadKeyCommon+0x22e
19 ffffe203`7fac33c0 fffff801`6aec2aa4     nt!CmLoadKey+0x25d
1a ffffe203`7fac3650 fffff801`6afeab50     nt!CmLoadDifferencingKey+0xa50
1b ffffe203`7fac39d0 fffff801`6ac2b6e5     nt!NtLoadKey3+0x190
1c ffffe203`7fac3a70 00007ff9`a1551564     nt!KiSystemServiceCopyEnd+0x25
```

The proof of concept was successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715).

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.