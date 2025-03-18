# Windows Kernel out-of-bounds reads and other issues in applockerfltr!SmpRegistryCallback

The applockerfltr.sys driver is one of the default drivers present in a standard Windows 10/11 installation, and is related to the AppLocker / Smart App Control functionality. It registers a registry callback named SmpRegistryCallback, which is responsible for monitoring the registry for changes to values named "UninstallString" within several specific paths like \REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall and several others. Once it detects a RegNtPreSetValueKey operation with the right name and a type of REG_SZ/REG_EXPAND_SZ, it proceeds to remove all trailing null characters from the end of the value's data buffer, as illustrated in the C-like pseudo code below:

```c
NTSTATUS SmpRegistryCallback(REG_NOTIFY_CLASS NotifyClass, REG_SET_VALUE_KEY_INFORMATION *KeyInfo)
{
  // ...

  USHORT DataSize = (USHORT)KeyInfo->DataSize;
  PWCHAR Data = KeyInfo->Data;

  if (DataSize < 4) {
    return STATUS_SUCCESS;
  }

  UNICODE_STRING StrippedDataString;
  StrippedDataString.MaximumLength = DataSize;
  StrippedDataString.Buffer = Data;

  while (Data[(DataSize / 2) - 1] == 0) {
    DataSize--;
  }

  StrippedDataString.Length = DataSize;

  // ...
}
```

As we can see, the problem with the 'while' loop is that its only exit condition is one of the characters in the data buffer being non-zero. But this is not guaranteed, and a local attacker can pass an input buffer filled solely with zeros. As a result, when the DataSize variable reaches a value of zero, the code starts to access out-of-bounds memory, first at offset -1 of the array, and then possibly, if DataSize underflows, offsets 0x7FFE, 0x7FFD, and so on. If the entire 64 KiB region pointed to by `Data` is filled with zeros, the loop can execute indefinitely. However, if a non-zero 16-bit character is encountered somewhere in the out-of-bounds data, the kernel exits the loop with `DataSize` set to an inadequately large value, which is then assigned to `StrippedDataString.Length`. If several other conditions are met, the `StrippedDataString` object is passed further down to applockerfltr!SmRegisterUninstallStringWithSessionOrigin -> applockerfltr!SmAllocUninstallStringData -> appid!AiAllocUninstallStringData, where a copy of the invalid string is made and stored in the internal AppID data structures. The end result of the bug is an OOB read from the kernel stack or the kernel pools (depending on the length of the data and where the NtSetValueKey syscall handler allocates it), but it is not entirely clear to me if/how the OOB data could find its way back to an unprivileged user to allow for memory disclosure.

In addition to the missing exit condition in the 'while' loop, there are a few other minor issues in the same function:

1) There is no verification that DataSize is even, but the routine itself and various unicode-related helpers rely on it, so it should be checked early in the callback execution.
2) The REG_SET_VALUE_KEY_INFORMATION.DataSize field is immediately cast to the 16-bit USHORT type, but it is in fact a 32-bit member whose value may easily exceed the 16-bit integer range. This could possibly lead to some memory safety issues in the future.
3) Further in the function, the driver obtains the key's full path using the CmCallbackGetKeyObjectID API, and checks whether it falls within one of four specific paths. But two of the four template paths are \REGISTRY\USER\Software\Microsoft\Windows\CurrentVersion\Uninstall and \REGISTRY\USER\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall, which are obviously invalid, because they are missing the user's SID string that always goes between the "USER" and "Software" components of the path. It is a functional bug that causes these two locations to not be effectively monitored.

Attached is a proof-of-concept exploit for the main issue described in this report, the out-of-bounds read. It has been successfully tested on Windows 11 24H2 (February 2025 update, build 26100.3194). It works by creating a volatile "Test" key in the user's HKCU, and trying to set a value named "UninstallString" filled with 0x1000004 (~16 MiB) zero bytes. In my test environment, the operation is intercepted by applockerfltr's callback, and a system crash occurs when attempting to dereference index -1 of the Data array. An example crash log is shown below:

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced.  This cannot be protected by try-except.
Typically the address is just plain bad or it is pointing at freed memory.
Arguments:
Arg1: ffffe18d7efffffe, memory referenced.
Arg2: 0000000000000000, value 0 = read operation, 1 = write operation.
Arg3: fffff801807474d8, If non-zero, the instruction address which referenced the bad memory
	address.
Arg4: 0000000000000002, (reserved)

[...]

TRAP_FRAME:  fffffe09a96d8500 -- (.trap 0xfffffe09a96d8500)
NOTE: The trap frame does not contain all registers.
Some register values may be zeroed or incorrect.
rax=0000000000000000 rbx=0000000000000000 rcx=0000000000000000
rdx=0000000000000000 rsi=0000000000000000 rdi=0000000000000000
rip=fffff801807474d8 rsp=fffffe09a96d8690 rbp=fffffe09a96d86e0
 r8=ffffe18d7f000000  r9=fffff80180743560 r10=fffff801eaec0960
r11=ffffad8460cb0080 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
applockerfltr!SmpRegistryCallback+0xc8:
fffff801`807474d8 6645396440fe    cmp     word ptr [r8+rax*2-2],r12w ds:ffffe18d`7efffffe=????
Resetting default scope

STACK_TEXT:  
fffffe09`a96d7a68 fffff801`eab70812     : fffffe09`a96d7ae8 00000000`00000001 00000000`00000080 fffff801`eac92a01 : nt!DbgBreakPointWithStatus
fffffe09`a96d7a70 fffff801`eab6fd3c     : 00000000`00000003 fffffe09`a96d7bd0 fffff801`eac92bf0 fffffe09`a96d8190 : nt!KiBugCheckDebugBreak+0x12
fffffe09`a96d7ad0 fffff801`eaab8567     : 00000000`00000000 fffff801`ea8d482a ffffe18d`7efffffe 00000000`00000003 : nt!KeBugCheck2+0xb2c
fffffe09`a96d8260 fffff801`ea8d3c85     : 00000000`00000050 ffffe18d`7efffffe 00000000`00000000 fffffe09`a96d8500 : nt!KeBugCheckEx+0x107
fffffe09`a96d82a0 fffff801`ea87a51f     : ffffe18d`7efffffe 00000000`00001000 00000000`00000002 fffff801`ea600000 : nt!MiSystemFault+0x735
fffffe09`a96d8390 fffff801`eac880cb     : 00000000`00000001 00000000`00000000 fffffe09`a96d8631 fffff801`eaa0d789 : nt!MmAccessFault+0x2ff
fffffe09`a96d8500 fffff801`807474d8     : fffffe09`a96d8980 fffffe09`a96d86e0 00000000`00000000 ffffe18d`79dbcdc0 : nt!KiPageFault+0x38b
fffffe09`a96d8690 fffff801`eae2ae3e     : ffffe18d`7e58b390 fffffe09`a96d8b00 00000000`00000001 00000000`00000000 : applockerfltr!SmpRegistryCallback+0xc8
fffffe09`a96d8720 fffff801`eae67926     : 00000000`00000001 fffffe09`a96d8980 00000000`00000000 ffffad84`628cf001 : nt!CmpCallCallBacksEx+0x6ce
fffffe09`a96d8830 fffff801`eac8c555     : 00000000`00000000 00000000`00000019 00000000`00000000 00000000`00000000 : nt!NtSetValueKey+0x5d6
fffffe09`a96d8a70 00007ffb`4cf403c4     : 00007ffb`4a3a662a 00000000`000f003f 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
0000000c`94d0fb58 00007ffb`4a3a662a     : 00000000`000f003f 00000000`00000000 00000000`00000000 0000000c`94d0fcd0 : ntdll!NtSetValueKey+0x14
0000000c`94d0fb60 00007ffb`4a3a6284     : 00000000`00000000 00000000`00000000 00000000`00000000 0000019e`8f9fc040 : KERNELBASE!BaseRegSetValueInternal+0x13a
0000000c`94d0fbf0 00007ff6`ceaf1136     : 00000000`000000e8 0000019e`8f9fc040 00000000`00000000 00000000`00000000 : KERNELBASE!RegSetValueExW+0x2b4
0000000c`94d0fc80 00000000`000000e8     : 0000019e`8f9fc040 00000000`00000000 00000000`00000000 0000019e`8f9fc040 : ApplockerfltrCrash+0x1136
0000000c`94d0fc88 0000019e`8f9fc040     : 00000000`00000000 00000000`00000000 0000019e`8f9fc040 1f8bfbff`01000004 : 0xe8
0000000c`94d0fc90 00000000`00000000     : 00000000`00000000 0000019e`8f9fc040 1f8bfbff`01000004 00000000`00000000 : 0x0000019e`8f9fc040
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.