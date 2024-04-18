# Windows Kernel NULL pointer dereference in NtDeleteValueKey

We have discovered that on Windows Server 2019, the `NtDeleteValueKey` system call handler is affected by a minor bug when operating on the input value name. According to MSDN, its declaration is as follows:

```c
NTSYSAPI NTSTATUS ZwDeleteValueKey(
  [in] HANDLE          KeyHandle,
  [in] PUNICODE_STRING ValueName
);
```

The problem is that the syscall tries to determine whether the `ValueName` string needs to be captured from user-mode based on whether the `UNICODE_STRING.Buffer` member is NULL, instead of whether the `UNICODE_STRING.Length` member is zero. As a result, it is possible for a user-mode program to pass a specially crafted `UNICODE_STRING` structure with non-zero length and `Buffer=NULL`, and such a representation will be successfully propagated to a kernel copy of the structure. But this combination of values is invalid and generally unexpected by the kernel, so when the code tries to perform some basic processing of the string a few instructions later (in this case, stripping trailing nul characters), it crashes with an unhandled exception while reading from a near-zero address.

We have confirmed the bug on Windows Server 2019, and have also found that it is fixed in the more recent Windows 11. We didn't investigate other versions of the OS. Due to existing mitigations restricting the ability to map near-NULL pages by user-mode programs in modern versions of Windows, we assess the impact of the bug as a local denial of service.

Attached is a proof-of-concept exploit, which has been successfully tested on Windows Server 2019 (November 2023 update, build 17763.5122). An example crash log is shown below:

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

SYSTEM_SERVICE_EXCEPTION (3b)
An exception happened while executing a system service routine.
Arguments:
Arg1: 00000000c0000005, Exception code that caused the bugcheck
Arg2: fffff80756472fe8, Address of the instruction which caused the bugcheck
Arg3: fffffd01b67fdf90, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  fffffd01b67fdf90 -- (.cxr 0xfffffd01b67fdf90)
rax=0000000000810000 rbx=000000000000ccce rcx=000000000000cccc
rdx=000000000000ccce rsi=0000000000000000 rdi=0000000000000000
rip=fffff80756472fe8 rsp=fffffd01b67fe980 rbp=fffffd01b67feb80
 r8=00007fffffff0000  r9=fffff80755e1c000 r10=fffffd01b67fe900
r11=ffffb78b72fe6000 r12=0000000000000001 r13=0000000000000000
r14=0000000000000000 r15=0000005c9e36f888
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010282
nt!NtDeleteValueKey+0x368:
fffff807`56472fe8 663939          cmp     word ptr [rcx],di ds:002b:00000000`0000cccc=????
Resetting default scope

PROCESS_NAME:  ValueNullPtrDeref.exe

STACK_TEXT:  
fffffd01`b67fe980 fffff807`55fe88f5     : ffffcd0c`a643a080 00000000`00000001 ffffcd0c`a643a080 00000000`00000000 : nt!NtDeleteValueKey+0x368
fffffd01`b67feb00 00007ffc`2af71604     : 00007ff6`78ad10f4 00007ff6`78ae62b0 00000000`00000000 00020800`000a0652 : nt!KiSystemServiceCopyEnd+0x25
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.