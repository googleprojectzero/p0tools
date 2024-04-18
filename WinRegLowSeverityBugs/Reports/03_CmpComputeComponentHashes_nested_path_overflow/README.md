# Windows Kernel pool-based buffer overflow when parsing deeply nested key paths in CmpComputeComponentHashes

According to the "Registry element size limits" article on MSDN:

```
A registry tree can be 512 levels deep. You can create up to 32 levels at a time through a single registry API call.
```

A single relative key path in the Windows kernel is represented by an undocumented structure I have called `_CM_PATH_INFO`. Its prototype is not available in Microsoft's public symbols for the kernel, but I've reverse-engineered it and arrived at the following definition:

```c
struct _CM_PATH_INFO {
  DWORD Hashes[8];
  UNICODE_STRING Components[8];
  _CM_LONG_PATH_INFO *LongPathInfo;
};
```

This structure is capable of storing key paths with up to eight elements: the `Hashes` member stores the 32-bit hashes of each key name, and `Components` is an array of UNICODE_STRING structures pointing to the corresponding portions of the key paths. For example when operating on a path of "A\B\C", `Components[0]` will point to "A", `Components[1]` to "B" and `Components[2]` to "C". If the given path is deeper than eight levels, a second structure is dynamically allocated and pointed to by `LongPathInfo`:

```c
struct _CM_LONG_PATH_INFO {
  DWORD Hashes[24];
  UNICODE_STRING Components[24];
};
```

This adds the capacity for 24 additional elements, for a total of 32 levels. The most important kernel functions that operate on these structures are `CmpComputeComponentHashes`, `CmpValidateComponents`, `CmpExpandPathInfo`, `CmpGetComponentNameAtIndex`, `CmpGetComponentHashAtIndex` and `CmpCleanupPathInfo`. The issue discussed in this report is found in `CmpComputeComponentHashes`, which is responsible for splitting an input key path into individual key names and initializing the `_CM_PATH_INFO` structure with them. There is an off-by-one bug that allows an attacker to overflow the `_CM_LONG_PATH_INFO` structure by writing to `_CM_LONG_PATH_INFO.Hashes[24]` (an intra-structure overflow) and to `_CM_LONG_PATH_INFO.Components[24]` (a typical pool-based buffer overflow).

The high-level algorithm implemented by CmpComputeComponentHashes is as follows:

1. Iterate over the input string character-by-character. Whenever a `\` is encountered, fill in information about the preceding component. Stop when 32 components have been reached or the whole input string has been processed.
2. If we've successfully processed the entire string, add the last component of the path to the output structure (e.g. the "C" in "A\B\C").

The problem here seems to be that the function assumes that "32 components reached" and "processed whole string" are mutually exclusive conditions, and if the latter is true, it is safe to add one last element to the array without performing adequate bounds checking. But consider the following path consisting of 32 keys named "A" split by 31 backslashes, with an extra backslash at the end:

```
A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\A\
```

When faced with such a string, and after reaching its last character, both conditions become true at the same time. The entirety of `_CM_PATH_INFO` and `_CM_LONG_PATH_INFO` are filled with data, but the function still decides to execute step 2 and add one last extra entry corresponding to an empty string - the supposed trailing component after the last backslash. Specifically, this means writing 0x0 to `_CM_LONG_PATH_INFO.Hashes[24]` (the hash of an empty string is always zero), and initializing `_CM_LONG_PATH_INFO.Components[24]` to an empty string.

In terms of reaching `CmpComputeComponentHashes` with a suitable input, there are two callers of the function in the kernel: `CmpDoParseKey` and `CmpGetSymbolicLinkTarget`. After a brief investigation, we have found that the condition is not reachable via `CmpDoParseKey`, because it strips all trailing backslashes from the path before passing it to `CmpComputeComponentHashes`. This leaves us with `CmpGetSymbolicLinkTarget`, which reads the data of the "SymbolicLinkValue" value from the symlink being resolved, and uses it as input to the vulnerable function without any further processing. This is an ideal candidate for reproducing the bug, and it is indeed what the attached proof-of-concept exploit (`PathInfoOverflow`) uses to trigger the buffer overflow. It has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715).

What comes as a surprise is the fact that even though our PoC triggers the out-of-bounds write, it doesn't lead to a kernel crash, even with Special Pools enabled for ntoskrnl.exe. Here's why: the `_CM_LONG_PATH_INFO` structure is 0x1E0 bytes long, but it is not allocated directly from the kernel pools with a call such as `ExAllocatePoolWithTag`. Instead, it is allocated in `CmpExpandPathInfo` from `PCRB.PPLookasideList[LookasideScratchBufferList]`, a lookaside list of scratch buffers of size 0x4F0 (initialized in `ExInitPoolLookasidePointers`):

```
0: kd> !pool ffffb98851f06b10
Pool page ffffb98851f06b10 region is Special pool
*ffffb98851f06000 size:  4f0 data: ffffb98851f06b10 (NonPaged) *Scbf
		Pooltag Scbf : Mass storage driver tags
```

As a result, the extra unused 0x310 bytes at the end of the allocation absorb the 0x10-byte long overflow and neutralize any of the security impact. Furthermore, the intra-structure corruption caused by writing 0x0 to `_CM_LONG_PATH_INFO.Hashes[24]` overlaps with `_CM_LONG_PATH_INFO.Components[0].{Length,MaximumLength}`, and we haven't found any way to convert the primitive of zeroing the length of the first component into any kind of meaningful memory safety violation either. Therefore, in our assessment, it seems that the bug is currently not exploitable due to the specifics of the allocator and the structure memory layout, but we believe it should nevertheless be addressed, as any unrelated change in nearby code may quietly make the condition exploitable in the future.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.