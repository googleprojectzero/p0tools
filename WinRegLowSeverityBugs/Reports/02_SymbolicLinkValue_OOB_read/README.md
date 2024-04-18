# Windows Kernel out-of-bounds read when validating symbolic links in CmpCheckValueList

When loading a new hive from disk, the Windows kernel validates the structure of the hive to make sure it is formatted correctly and adheres to all of the registry-specific requirements. One such requirement is that if a registry key is a symbolic link (it has the 0x10 flag set in `_CM_KEY_NODE.Flags`), then it may contain no more than one value, and that value must be named "SymbolicLinkValue". This is indeed enforced in the internal kernel function `CmpCheckValueList`, but there is a bug: the code simply compares the `_CM_KEY_VALUE.Name` buffer with the 17-byte ASCII string "SymbolicLinkValue", but doesn't take other aspects of the value cell into account:

1. It assumes that the name is compressed (i.e. represented as 8-bit ASCII) while in fact it may be a 16-bit wide char string (if the 0x1 flag is clear in `_CM_KEY_VALUE.Flags`).
2. It assumes that the name length is 17 characters, while in fact it may be arbitrarily shorter or longer.

This may lead to two problems. Firstly, the check can be effectively bypassed by manipulating the length and compression flag, making it possible to have a symlink key with a value named differently than "SymbolicLinkValue". Secondly, if the actual name of the value is shorter than 17 bytes and the value cell is placed right at the end of the last bin in the hive, the check will cause an out-of-bounds read relative to the hive mapping. However, because the presumed `memcmp()` call is inlined by the compiler as two 64-bit comparisons and one 8-bit comparison, together with the 8-byte alignment of cells, this makes any potential information disclosure likely impractical. We believe that the best an attacker could do is to leak whether the first eight bytes of the adjacent memory page are equal to "Symbolic" or "LinkValu", or whether the first byte of the next page is equal to "e".

Attached is a specially crafted hive file containing a symbolic link key and its corresponding REG_LINK value with a truncated "Symbolic" name placed at the end of the bin, together with a simple command line program to load it as an app hive. In typical conditions, the hive mapping is followed by unmapped memory and the invalid access leads to a kernel bugcheck. An example crash log, generated on Windows 11 22H2 (November 2023 update, build 22621.2715), is shown below:

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
Arg2: fffff8005f0d7a57, Address of the instruction which caused the bugcheck
Arg3: fffffb07d06ad040, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  fffffb07d06ad040 -- (.cxr 0xfffffb07d06ad040)
rax=ffffdc09ada1a000 rbx=fffffb07d06add78 rcx=0000000000000000
rdx=0000000000000001 rsi=ffffdc09ad5cb3e0 rdi=ffffdc09ad82e08c
rip=fffff8005f0d7a57 rsp=fffffb07d06ada60 rbp=fffffb07d06adb39
 r8=0000000000000008  r9=0000000000000001 r10=ffffdc09ad82e000
r11=0000000000000001 r12=0000000000000000 r13=ffffdc09ad82e000
r14=0000000000000fe0 r15=000001b30cdd1fe4
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050246
nt!CmpCheckValueList+0x19ab77:
fffff800`5f0d7a57 498b4f1c        mov     rcx,qword ptr [r15+1Ch] ds:002b:000001b3`0cdd2000=????????????????
Resetting default scope

PROCESS_NAME:  Registry

STACK_TEXT:  
fffffb07`d06ada60 fffff800`5ef3b593     : ffffdc09`ad82e000 ffffdc09`ad82e000 ffffdc09`ad5cb3e0 00000000`ffffffff : nt!CmpCheckValueList+0x19ab77
fffffb07`d06adb80 fffff800`5ef3da16     : ffffdc09`ad82e000 00000000`03190001 ffffdc09`000000f0 00000000`00000078 : nt!CmpCheckKey+0xf63
fffffb07`d06adc80 fffff800`5ef7b5c0     : ffffdc09`00000001 ffffdc09`03190001 fffffb07`d06add78 fffffb07`00000000 : nt!CmpCheckRegistry2+0xe6
fffffb07`d06add30 fffff800`5ee8ff2c     : 00000000`00000000 fffffb07`03190001 00000000`00000000 ffffdc09`00010000 : nt!CmCheckRegistry+0x178
fffffb07`d06ade00 fffff800`5ee8ccd1     : fffffb07`d06ae788 ffffa406`78cfd001 00000000`03190001 fffffb07`d06ae0d4 : nt!CmpCreateHive+0x474
fffffb07`d06ae060 fffff800`5ee8ca2d     : 00000000`00000000 fffff800`5ef42437 fffffb07`d06ae3c0 fffffb07`d06ae3a8 : nt!CmpInitHiveFromFile+0x225
fffffb07`d06ae230 fffff800`5eeb70c8     : ffffffff`ffffffff fffff800`5f413d00 00000000`00000180 ffffdc09`aa7d1000 : nt!CmpCmdHiveOpen+0xd9
fffffb07`d06ae320 fffff800`5eec2765     : 00000000`00000000 fffffb07`00000010 00000000`00000000 00000000`00000001 : nt!CmLoadAppKey+0x2cc
fffffb07`d06ae680 fffff800`5eec33fd     : 00007ffc`fc379860 00000000`00000014 fffffb07`d06aeae0 ffff803f`fe7e1bc8 : nt!CmLoadDifferencingKey+0x711
fffffb07`d06aea00 fffff800`5ec2b6e5     : 00000000`00000000 00000000`00000000 00000000`00000000 00000088`b8cff2a8 : nt!NtLoadKeyEx+0x5d
fffffb07`d06aea70 00007ffc`feb31584     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.