# Windows Kernel out-of-bounds read of key node security in CmpValidateHiveSecurityDescriptors when loading corrupted hives

One of the first steps when loading a new registry hive from disk in Windows is to verify its structural correctness in the internal `CmCheckRegistry` kernel function. After checking the bin and cell-level correctness, the routine validates the security descriptors by calling `CmpValidateHiveSecurityDescriptors`. The latter function then proceeds to resolve the root key node and its security descriptor cell index, and then traverses the linked list and validates each descriptor found on its way.

The problem described in this report is the fact that `CmpValidateHiveSecurityDescriptors` accesses the `_CM_KEY_NODE.Security` member (at offset 0x2C) of the root key node without first making sure that the cell pointed to by `_HHIVE.BaseBlock.RootCell` is at least 76 bytes long (the smallest valid size of `_CM_KEY_NODE`). Such a check does indeed occur later in the code while checking each key in the key tree as part of `CmpCheckKey`, but that only happens after the execution of `CmpValidateHiveSecurityDescriptors` -- and before that, there are no guarantees regarding the structure of any particular key node. Therefore, if an attacker attempts to load a corrupted hive with the `RootCell` pointing at a valid but small (e.g. four bytes) cell right at the end of the last bin, the access to `_CM_KEY_NODE.Security` will result in reading memory outside the bounds of the hive mapping.

Straightforward exploitation of the bug is largely prevented by the fact that even if `CmpValidateHiveSecurityDescriptors` doesn't crash and completes successfully, the subsequent call to `CmpCheckKey` will immediately spot that the root cell is not a valid key node structure and will reject the hive as a whole. This severely limits the ability to leak any data directly, but the issue does show some potential for indirect exploitation, because:

- It is possible that a view of a more privileged hive (e.g. a system or another user's hive) will be mapped directly adjacent to the attacker's hive in the user address space of the Registry process, making the out-of-bounds `_CM_KEY_NODE.Security` member point into sensitive data from another security context,
- It is likely possible to infer some properties of the uint32 value via side channels, e.g. by timing whether the call `HvIsCellAllocated(_CM_KEY_NODE.Security)` succeeded or failed, and whether it was processed further as a seemingly valid security cell or not.

As shown above, it seems theoretically possible to disclose a limited amount of information from an external hive by abusing this bug, but we haven't further investigated the practical chances or specific exploitation techniques. We are leaving it up to MSRC to assess whether this issue warrants a fix in a security bulletin or not.

Attached is a specially crafted hive file with a small root cell placed at the end of the bin, and a simple command line program to load it as an app hive. In typical conditions, the hive mapping is followed by unmapped memory and the invalid access leads to a kernel bugcheck. An example crash log, generated on Windows 11 22H2 (November 2023 update, build 22621.2715), is shown below:

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
Arg2: fffff805724b84c6, Address of the instruction which caused the bugcheck
Arg3: ffffd6000807c270, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  ffffd6000807c270 -- (.cxr 0xffffd6000807c270)
rax=0000026af0181ffc rbx=ffff918df5559000 rcx=ffff918df5559000
rdx=0000026af0181000 rsi=0000026af0181ffc rdi=ffffd6000807cd78
rip=fffff805724b84c6 rsp=ffffd6000807cc90 rbp=ffffd6000807cce8
 r8=ffffd6000807ccd4  r9=0000000000000000 r10=ffff918df5559000
r11=0000000000000ff8 r12=ffffd6000807cd78 r13=ffff918df76d1300
r14=ffff918df2ced5b0 r15=0000000000000040
iopl=0         nv up ei pl nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050206
nt!CmpValidateHiveSecurityDescriptors+0xe6:
fffff805`724b84c6 448b662c        mov     r12d,dword ptr [rsi+2Ch] ds:002b:0000026a`f0182028=????????
Resetting default scope

PROCESS_NAME:  Registry

STACK_TEXT:  
ffffd600`0807cc90 fffff805`7257b589     : ffff918d`f5559000 ffff918d`03190001 ffffd600`0807ce00 ffffd600`0807cd78 : nt!CmpValidateHiveSecurityDescriptors+0xe6
ffffd600`0807cd30 fffff805`7248ff2c     : 00000000`00000000 ffffd600`03190001 00000000`00000000 ffff918d`00010000 : nt!CmCheckRegistry+0x141
ffffd600`0807ce00 fffff805`7248ccd1     : ffffd600`0807d788 ffff800f`2a4fb001 00000000`03190001 ffffd600`0807d0d4 : nt!CmpCreateHive+0x474
ffffd600`0807d060 fffff805`7248ca2d     : 00000000`00000000 fffff805`72542437 ffffd600`0807d3c0 ffffd600`0807d3a8 : nt!CmpInitHiveFromFile+0x225
ffffd600`0807d230 fffff805`724b70c8     : ffffffff`ffffffff fffff805`72a13d00 00000000`00000180 ffff918d`ec372000 : nt!CmpCmdHiveOpen+0xd9
ffffd600`0807d320 fffff805`724c2765     : 00000000`00000000 ffffd600`00000010 00000000`00000000 00000000`00000001 : nt!CmLoadAppKey+0x2cc
ffffd600`0807d680 fffff805`724c33fd     : 00007ff8`35b09860 00000000`00000014 ffffd600`0807dae0 ffffc13f`fc1ad848 : nt!CmLoadDifferencingKey+0x711
ffffd600`0807da00 fffff805`7222b6e5     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!NtLoadKeyEx+0x5d
ffffd600`0807da70 00007ff8`38791584     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.