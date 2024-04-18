# Windows Kernel user-triggerable crash in CmpKeySecurityIncrementReferenceCount via unreferenced security descriptors

In the recent months, new hardening measures have been introduced in the Windows kernel to limit the exploitability of vulnerabilities related to security descriptors in registry hives. One example of such a measure is the `CmpKeySecurityIncrementReferenceCount` kernel function, whose goal is to safely reference a given security descriptor when a new key gets associated with it. In addition to incrementing `_CM_KEY_SECURITY.ReferenceCount`, it features two extra checks:

1. If the old value of the refcount is zero, a `REGISTRY_ERROR` bugcheck is generated.
2. If the old value of the refcount is 0xffffffff (i.e. incrementing it would overflow the uint32), the function returns `STATUS_INTEGER_OVERFLOW`.

Check #2 is indeed very effective in preventing refcount overflows and any ensuing use-after-frees. We assume that check #1 is supposed to be a last-resort assertion to detect an abnormal situation in which the refcount has already been overflown (maybe by some other code in the kernel), and the attacker is just about to exploit this condition. At first glance, this may appear to be a valid approach considering the fact that non-referenced security descriptors never occur in hives organically: under normal circumstances, whenever an SD's refcount drops to zero, it is immediately freed and removed from the descriptor list.

However, an unused security descriptor with a zero refcount is not a fundamentally invalid construct, and there are a few techniques a local user can employ to reach such a state in the registry. The easiest one is to simply load a custom hive that has a security descriptor with `refcount=0` using the `RegLoadAppKey` API - such a descriptor won't be rejected during hive loading and will remain present in the hive ready to be referenced in the future. If `CmpKeySecurityIncrementReferenceCount` ever got called on such a descriptor, it would immediately crash the system even though no overflow has taken place - the zero refcount simply represents a legitimate lack of references to it.

At the time of this writing this won't work though, because adding references to security descriptors is scattered across the kernel, and `CmpKeySecurityIncrementReferenceCount` is not uniformly used in all cases. Currently, it is called from two sites: `CmpCheckKey` and `CmRenameKey` via `CmpReferenceSecurityNode`. In the latter case, it is impossible for the reference count to be zero, so the only other option is `CmpCheckKey`. There, it is used to increment the refcount of the parent key's descriptor if a subkey has a corrupted security cell index and must inherit the parent's security as part of the self-healing process. Here, it is indeed possible to reach `CmpKeySecurityIncrementReferenceCount` with `refcount=0`, by loading a hive with the following structure:

- `ROOT` key, with a valid security cell index pointing to a descriptor with `ReferenceCount=0`
- `ROOT\SubKey` key, with an invalid security cell index specified in `_CM_KEY_NODE.Security`

This is exactly what the attached proof-of-concept exploit does. It has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715), and an example crash log is shown below:

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

REGISTRY_ERROR (51)
Something has gone badly wrong with the registry.  If a kernel debugger
is available, get a stack trace. It can also indicate that the registry got
an I/O error while trying to read one of its files, so it can be caused by
hardware problems or filesystem corruption.
It may occur due to a failure in a refresh operation, which is used only
in by the security system, and then only when resource limits are encountered.
Arguments:
Arg1: 0000000000000004, (reserved)
Arg2: 0000000000000006, (reserved)
Arg3: ffffe60976165000, depends on where Windows bugchecked, may be pointer to hive
Arg4: 0000000000000078, depends on where Windows bugchecked, may be return code of
	HvCheckHive if the hive is corrupt.

[...]

STACK_TEXT:  
ffff9088`dc213328 fffff806`7e166882     : ffff9088`dc213490 fffff806`7df1afa0 fffff806`7b6cb180 00000000`00000001 : nt!DbgBreakPointWithStatus
ffff9088`dc213330 fffff806`7e165f43     : fffff806`00000003 ffff9088`dc213490 fffff806`7e02fc70 00000000`00000051 : nt!KiBugCheckDebugBreak+0x12
ffff9088`dc213390 fffff806`7e016a87     : ffffe609`76165000 00000000`00000000 ffffe609`76165000 00000000`00000000 : nt!KeBugCheck2+0xba3
ffff9088`dc213b00 fffff806`7e011fd0     : 00000000`00000051 00000000`00000004 00000000`00000006 ffffe609`76165000 : nt!KeBugCheckEx+0x107
ffff9088`dc213b40 fffff806`7e33b064     : ffffe609`76165000 00000000`00000000 ffffe609`756f93e0 00000000`ffffffff : nt!CmpKeySecurityIncrementReferenceCount+0x48
ffff9088`dc213b80 fffff806`7e33da16     : ffffe609`76165000 00000000`03190001 ffffe609`000000f0 00000000`00000078 : nt!CmpCheckKey+0xa34
ffff9088`dc213c80 fffff806`7e37b5c0     : ffffe609`00000001 ffffe609`03190001 ffff9088`dc213d78 ffff9088`00000000 : nt!CmpCheckRegistry2+0xe6
ffff9088`dc213d30 fffff806`7e28ff2c     : 00000000`00000000 ffff9088`03190001 00000000`00000000 ffffe609`00010000 : nt!CmCheckRegistry+0x178
ffff9088`dc213e00 fffff806`7e28ccd1     : ffff9088`dc214788 ffff8006`e8afd001 00000000`03190001 ffff9088`dc2140d4 : nt!CmpCreateHive+0x474
ffff9088`dc214060 fffff806`7e28ca2d     : 00000000`00000000 fffff806`7e342437 ffff9088`dc2143c0 ffff9088`dc2143a8 : nt!CmpInitHiveFromFile+0x225
ffff9088`dc214230 fffff806`7e2b70c8     : ffffffff`ffffffff fffff806`7e813d00 00000000`00000180 ffffe609`74124000 : nt!CmpCmdHiveOpen+0xd9
ffff9088`dc214320 fffff806`7e2c2765     : 00000000`00000000 ffff9088`00000010 00000000`00000000 00000000`00000001 : nt!CmLoadAppKey+0x2cc
ffff9088`dc214680 fffff806`7e2c33fd     : 00007ffa`9ea49860 00000000`00000014 ffff9088`dc214ae0 ffffd5bf`fd4f5248 : nt!CmLoadDifferencingKey+0x711
ffff9088`dc214a00 fffff806`7e02b6e5     : 00000000`00000000 00000000`00000000 00000000`00000000 000000f3`730ff918 : nt!NtLoadKeyEx+0x5d
ffff9088`dc214a70 00007ffa`a1471584     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

Due to the fact that this issue allows a local attacker to crash the operating system, we assess the impact of the bug as a local denial of service.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.