# Windows Kernel NULL pointer dereference in CmpLightWeightPrepareSetSecDescUoW

According to my analysis, as part of fixing a security descriptor reference count leak in `CmpCleanupLightWeightPrepare` (issue #2410 / CVE-2023-28248), some broader changes were introduced in the Windows kernel in April 2023. Specifically, the `_CM_UOW_SET_SD_DATA` structure was extended to contain a `_HHIVE*` pointer, and the `CmpLightWeightCleanupSetSecDescUoW` routine was added to cleanly destroy the structure. Its pseudo-code can be expressed as follows:

```c
VOID CmpLightWeightCleanupSetSecDescUoW(_CM_UOW_SET_SD_DATA *SecurityData) {
  if (SecurityData->SecurityCell != -1) {
    CmpDereferenceSecurityNode(SecurityData->Hive, SecurityData->SecurityCell);
  }
  ExFreePoolWithTag(SecurityData, 'wUMC');
}
```

Its three callers are: `CmpCleanupLightWeightUoWData`, `CmpLightWeightCommitSetSecDescUoW` and `CmpLightWeightPrepareSetSecDescUoW`. There is a problem in one of the code paths in `CmpLightWeightPrepareSetSecDescUoW`, which initializes the `_CM_UOW_SET_SD_DATA` to all zeroes but doesn't set `SecurityCell` to the special marker of -1. Later on, if the `CmpGetSecurityDescriptorNode` call fails to find or allocate a suitable security descriptor cell, then the cleanup error path is executed. The `_CM_UOW_SET_SD_DATA.SecurityCell` member remains equal to 0, so the `SecurityCell != -1` check in `CmpLightWeightCleanupSetSecDescUoW` passes, and `CmpDereferenceSecurityNode` is invoked with both arguments equal to zero. This results in an unhandled NULL pointer dereference exception while trying to access the `_HHIVE` structure at address NULL.

A failure of the `CmpGetSecurityDescriptorNode` function can be induced by exhausting the 2 GiB of the available hive storage space, which is indeed what the attached proof-of-concept exploit does. It has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715). An example crash log is shown below:

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
Arg2: fffff80261d55c63, Address of the instruction which caused the bugcheck
Arg3: fffff680edfb7e30, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  fffff680edfb7e30 -- (.cxr 0xfffff680edfb7e30)
rax=0000000000000000 rbx=0000000000000000 rcx=fffff680edfb8884
rdx=0000000000000000 rsi=ffffb98ff5df531c rdi=0000000000000000
rip=fffff80261d55c63 rsp=fffff680edfb8850 rbp=fffff680edfb88f8
 r8=0000000000000000  r9=7ffffffffffffffc r10=0000000000000000
r11=fffff680edfb8880 r12=0000000000118178 r13=ffffb98ff5e9e030
r14=000002805e7576d4 r15=000002805e84917c
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
nt!CmpDereferenceSecurityNode+0x1f:
fffff802`61d55c63 f6838c00000001  test    byte ptr [rbx+8Ch],1 ds:002b:00000000`0000008c=??
Resetting default scope

PROCESS_NAME:  Registry

STACK_TEXT:  
fffff680`edfb8850 fffff802`62425dc1     : 00000000`ffffffff ffffb98f`f5e9e030 00000000`00118178 00000000`00000000 : nt!CmpDereferenceSecurityNode+0x1f
fffff680`edfb8880 fffff802`624276fd     : 00000000`ffffffff ffffb98f`f37aa000 ffffb98f`f5df531c ffffb98f`f37aa000 : nt!CmpLightWeightCleanupSetSecDescUoW+0x19
fffff680`edfb88b0 fffff802`6241a8bb     : ffffb98f`f711e6d0 fffff802`000b19b8 fffff802`000b1208 00000001`00118178 : nt!CmpLightWeightPrepareSetSecDescUoW+0x99
fffff680`edfb8940 fffff802`6241a67d     : 00000000`00000000 fffff680`edfb8b01 fffff680`edfb8a20 00000000`00000001 : nt!CmpProcessLightWeightUOW+0x19f
fffff680`edfb8980 fffff802`6241a346     : ffffb98f`f4b846e0 00000000`00000000 00000000`00000000 fffff802`624f32de : nt!CmpPrepareLightWeightTransaction+0xb9
fffff680`edfb8a00 fffff802`6240b1ef     : 00000000`00000020 00000000`00000000 fffff680`edfb8b60 00000000`00000000 : nt!CmpCommitLightWeightTransaction+0x6a
fffff680`edfb8a50 fffff802`61e2b6e5     : 00000000`000000c8 ffffe606`83142080 00000000`00000000 00000051`00000001 : nt!NtCommitRegistryTransaction+0xbf
fffff680`edfb8ae0 00007ffb`5b6106a4     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

Due to existing mitigations restricting the ability to map near-NULL pages by user-mode programs in modern versions of Windows, we assess the impact of the bug as a local denial of service.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.