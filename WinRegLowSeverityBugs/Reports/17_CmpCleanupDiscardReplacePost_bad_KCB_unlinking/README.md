# Windows Kernel fails to correctly unlink KCBs from discard replace context in CmpCleanupDiscardReplacePost

Deleting a registry key in Windows that is part of a layered key tree (i.e. has other differencing hives overlaid on top of it) is a complex process that involves a special data structure called a "discard replace context". Its purpose is to replace the KCBs of all Merge-Unbacked keys on higher levels than the key being deleted with new KCBs so that the old ones can be marked as deleted. In essence, it is a doubly-linked list of KCBs, with the following structure layout:

```
nt!_CMP_DISCARD_AND_REPLACE_KCB_CONTEXT
   +0x000 BaseKcb          : Ptr64 _CM_KEY_CONTROL_BLOCK
   +0x008 PrepareStatus    : Int4B
   +0x010 ClonedKcbListHead : _LIST_ENTRY
```

There are four internal kernel functions involved in operating on this structure:

1. `CmpInitializeDiscardReplaceContext`: performs basic initialization.
2. `CmpPrepareDiscardAndReplaceKcbAndUnbackedHigherLayers`: allocates the new KCBs that will be used to replace the existing Merge-Unbacked KCBs, and connects them in a list.
3. `CmpCommitDiscardAndReplaceKcbAndUnbackedHigherLayers`: replaces the KCBs in the KCB tree.
4. `CmpCleanupDiscardReplaceContext`: cleans up the context and destroys any pending KCBs that may still be on the list.

Under normal circumstances, `CmpCommitDiscardAndReplaceKcbAndUnbackedHigherLayers` in step 3 unlinks all of the new KCBs from the list, so `CmpCleanupDiscardReplaceContext` doesn't have much work left to do. But in the rare case when either `CmpPrepareDiscardAndReplaceKcbAndUnbackedHigherLayers` fails mid-operation, or some other error occurs in between steps 2 and 3, `CmpCommitDiscardAndReplaceKcbAndUnbackedHigherLayers` may never execute and the burden of fully cleaning up the context lies on `CmpCleanupDiscardReplaceContext`, which in turn executes a `CmpCleanupDiscardReplacePost` callback on every pair of (higher-layer KCB, cloned KCB to be discarded). The problem described in this report is the fact that `CmpCleanupDiscardReplacePost` doesn't comprehensively reset the `LIST_ENTRY` structure used to link the KCBs together: it unlinks entries from the list by updating `_CMP_DISCARD_AND_REPLACE_KCB_CONTEXT.ClonedKcbListHead.Flink` (the forward pointer of the head of the list) and `_CM_KEY_CONTROL_BLOCK.ClonedListEntry.Blink` (the backward pointer of each KCB), but it doesn't update `_CM_KEY_CONTROL_BLOCK.ClonedListEntry.Flink` (the forward pointer of each KCB). The `ClonedListEntry` structure in KCB is part of a union and occupies the same space as the head of the key's body list (i.e. active handles to the key):

```
kd> dt _CM_KEY_CONTROL_BLOCK
nt!_CM_KEY_CONTROL_BLOCK
   [...]
   +0x078 KeyBodyListHead  : _LIST_ENTRY
   +0x078 ClonedListEntry  : _LIST_ENTRY
   [...]
```

Once the KCB's refcount reaches zero, the kernel tries to free it by calling `CmpFreeKeyControlBlock`. At the beginning of the routine, there is an assertion to make sure that the key body list is empty (i.e. there are no active handles associated with the key being freed), achieved by checking the expected value of `KCB.KeyBodyListHead.Flink`:

```c
if (Kcb->KeyBodyListHead.Flink != &Kcb->KeyBodyListHead) {
  KeBugCheckEx(REGISTRY_ERROR, 0x11, Kcb, 0, 0);
}
```

So if the bug in `CmpCleanupDiscardReplacePost` is triggered, then later `CmpFreeKeyControlBlock` may confuse the `KeyBodyListHead` member with `ClonedListEntry` and conclude that the key still has active references due to the insufficiently cleaned up `LIST_ENTRY` structure. Since these cloned KCBs are not visible in the global KCB tree and get almost immediately freed, we don't currently see a way to exploit the inconsistent state of the list entry for anything more than a local DoS due to the failed assertion, but we are submitting the issue to MSRC for their assessment.

The bug can be reliably reproduced by taking advantage of lightweight registry transactions. In this scenario, steps 2 (`CmpPrepareDiscardAndReplaceKcbAndUnbackedHigherLayers`) and 3 (`CmpCommitDiscardAndReplaceKcbAndUnbackedHigherLayers`) are called from different functions and are separated by the "prepare" handlers of other operations being part of the transaction. If the key deletion is followed by another operation that fails during the "prepare" phase (e.g. setting a very long value), then the `CmpCommitDiscardAndReplaceKcbAndUnbackedHigherLayers` routine is never reached and the temporary discard replace context is destroyed in `CmpCleanupDiscardReplaceContext`, as invoked by `CmpCleanupLightWeightPrepare`.

Attached is a proof-of-concept exploit that takes the following steps:

1. Creates volatile keys `HKCU\Test` and `HKCU\Test\SubKey`
2. Enumerates the `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` key in search of an active differencing hive loaded on top of HKCU, assuming there is only one user logged in at that time. In our testing there has always been at least one such hive loaded after signing in to a default installation of Windows 11 (for the Widgets app). If needed, it can also be manually triggered by starting a standard utility like Notepad or Paint.
3. Opens `HKCU\Test\SubKey` through the differencing hive, in order to ensure that the base key KCB has higher layers attached to it.
4. Creates a lightweight transaction.
5. Transactionally deletes the `HKCU\Test\SubKey` key.
6. Transactionally sets a very long value in `HKCU\Test` twice, to ensure that one of these steps will fail due to hive space constraints.
7. Attempts to commit the transaction, which triggers the bug.

Sometimes running the PoC will immediately crash the system, while in other instances the KCBs may be added to a delayed close queue and only get processed by `CmpFreeKeyControlBlock` after a while. In such a case, we have found that signing out as the current user may help, as this triggers the unloading of HKCU and expedites the processing of any associated KCBs.

An example crash log, generated on Windows 11 22H2 (January 2024 update, build 10.0.22621.3007), is shown below:

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
Arg1: 0000000000000011, (reserved)
Arg2: ffffd3015b5266c0, (reserved)
Arg3: 0000000000000000, depends on where Windows bugchecked, may be pointer to hive
Arg4: 0000000000000000, depends on where Windows bugchecked, may be return code of
	HvCheckHive if the hive is corrupt.

[...]

STACK_TEXT:  
ffff870e`88524fc8 fffff803`82b668e2     : ffff870e`88525130 fffff803`8291ae80 fffff803`7d3b0180 00000000`00000001 : nt!DbgBreakPointWithStatus
ffff870e`88524fd0 fffff803`82b65fa3     : fffff803`00000003 ffff870e`88525130 fffff803`82a301f0 00000000`00000051 : nt!KiBugCheckDebugBreak+0x12
ffff870e`88525030 fffff803`82a16c07     : ffffd301`00000000 00000000`00000000 ffffd301`5b5266c0 fffff803`82d37c22 : nt!KeBugCheck2+0xba3
ffff870e`885257a0 fffff803`82ef2fe0     : 00000000`00000051 00000000`00000011 ffffd301`5b5266c0 00000000`00000000 : nt!KeBugCheckEx+0x107
ffff870e`885257e0 fffff803`82ed5a7f     : 00000000`00000000 ffffd301`5b5266c0 ffff870e`88525b00 ffff870e`88525a20 : nt!CmpFreeKeyControlBlock+0x14eb50
ffff870e`88525820 fffff803`8301d596     : ffffd301`5b526738 00000000`c000009a ffffd301`00000401 00000000`38400000 : nt!CmpDereferenceKeyControlBlockWithLock+0x1a58fb
ffff870e`88525850 fffff803`8301d943     : ffffd301`5b510a20 ffffd301`5b52beb0 00000000`00000000 00000000`00000000 : nt!CmpCleanupDiscardReplacePost+0x46
ffff870e`88525880 fffff803`82eba466     : ffffd301`5b599bc0 fffff803`8301d5c0 fffff803`8301d550 ffff870e`88525b01 : nt!CmpEnumerateAllHigherLayerKcbs+0x137
ffff870e`885258d0 fffff803`8301a1c1     : ffffd301`5b0b96c0 ffff870e`88525a20 ffff870e`88525a20 fffff803`8301a703 : nt!CmpCleanupDiscardReplaceContext+0x200056
ffff870e`88525920 fffff803`8301a09d     : ffffd301`5b0fd440 ffff870e`00000000 ffff870e`88525960 ffff870e`88525960 : nt!CmpCleanupLightWeightUoWData+0xfd
ffff870e`88525950 fffff803`8301a623     : ffffd301`58e08e00 00000000`c000009a ffff870e`88525a20 00000000`00000001 : nt!CmpCleanupLightWeightPrepare+0x29
ffff870e`88525980 fffff803`8301a256     : ffffd301`5b140360 00000000`00000000 00000000`00000000 fffff803`830f32de : nt!CmpPrepareLightWeightTransaction+0x14f
ffff870e`88525a00 fffff803`8300b0ff     : ffff870e`88525a88 00000000`00000000 ffff870e`88525b60 fffff803`82a2bbe5 : nt!CmpCommitLightWeightTransaction+0x6a
ffff870e`88525a50 fffff803`82a2bbe5     : ffff870e`88525b60 ffffe30f`2adc8080 00000000`00000000 00000000`00000000 : nt!NtCommitRegistryTransaction+0xbf
ffff870e`88525ae0 00007ffb`bd5706a4     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

As a bonus, there also seems to be a NULL pointer dereference bug in the `CmpEnumerateAllHigherLayerKcbs` function, whenever the post-type callback (e.g. `CmpPrepareDiscardReplacePost`) returns TRUE, indicating that the enumeration should be aborted due to an error. Our cursory analysis implies that it may be a problem with traversing the lower/upper-layer structures (`_CM_KCB_LAYER_INFO`) of the key tree and the crash itself is caused by trying to dereference the `KCB->LayerInfo->LowerLayer` pointer of a base key, which is set to NULL. However, a more in-depth analysis is required to confirm this.

It can be reproduced with the `BadKcbUnlinking` proof-of-concept and WinDbg attached as a kernel debugger to the test system:

1. Set a breakpoint on the `CmpCloneToUnbackedKcb` function in WinDbg: `bp CmpCloneToUnbackedKcb`.
2. Resume the system: `g`.
3. Start the `BadKcbUnlinking.exe` program on the test system. The breakpoint on `CmpCloneToUnbackedKcb` should hit in WinDbg.
4. Clear the previous breakpoint: `bc 0`.
5. Set a new breakpoint on `CmpAllocateKeyControlBlock`: `bp CmpAllocateKeyControlBlock`.
6. Resume the system: `g`. The new breakpoint in `CmpAllocateKeyControlBlock` should hit.
7. Step out of the function: `gu`.
8. Simulate failure to allocate the KCB by setting the RAX register to zero: `r @rax=0`.
9. Clear the previous breakpoint: `bc 0`.
10. Resume the system: `g`.

At this point, you should observe the following kernel crash:

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
Arg2: fffff8046261d987, Address of the instruction which caused the bugcheck
Arg3: ffff9081ea259e10, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  ffff9081ea259e10 -- (.cxr 0xffff9081ea259e10)
rax=0000000000000002 rbx=0000000000000000 rcx=ffffbb88c308f000
rdx=ffff9081ea25a8c0 rsi=ffffbb88c50eddd0 rdi=0000000000000000
rip=fffff8046261d987 rsp=ffff9081ea25a830 rbp=0000000000000001
 r8=0000000000000001  r9=fffff8046261dd50 r10=ffff9081ea25a8c0
r11=0000000000000000 r12=ffff9081ea25a8c0 r13=ffffbb88c50eddd0
r14=ffffbb88c2f76c10 r15=0000000000000001
iopl=0         nv up ei pl nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050202
nt!CmpEnumerateAllHigherLayerKcbs+0x17b:
fffff804`6261d987 488b7f18        mov     rdi,qword ptr [rdi+18h] ds:002b:00000000`00000018=????????????????
Resetting default scope

PROCESS_NAME:  Registry

STACK_TEXT:  
ffff9081`ea25a830 fffff804`6261dd03     : 00000000`00000000 fffff804`6261d5c0 fffff804`6261dd50 ffffbb88`c308f000 : nt!CmpEnumerateAllHigherLayerKcbs+0x17b
ffff9081`ea25a880 fffff804`62626e5b     : 00000000`00000000 ffffbb88`c5415530 00000000`00000000 00000000`00000000 : nt!CmpPrepareDiscardAndReplaceKcbAndUnbackedHigherLayers+0x57
ffff9081`ea25a8e0 fffff804`6261a727     : ffffbb88`c5415440 00000000`00000000 00000000`ffffffff ffff9081`ea25ab01 : nt!CmpLightWeightPrepareDeleteKeyUoW+0x153
ffff9081`ea25a940 fffff804`6261a58d     : 00000000`00000000 ffff9081`ea25ab01 ffff9081`ea25aa20 00000000`00000001 : nt!CmpProcessLightWeightUOW+0xfb
ffff9081`ea25a980 fffff804`6261a256     : ffffbb88`c503d0e0 00000000`00000000 00000000`00000000 fffff804`626f32de : nt!CmpPrepareLightWeightTransaction+0xb9
ffff9081`ea25aa00 fffff804`6260b0ff     : ffff9081`ea25aa88 00000000`00000000 ffff9081`ea25ab60 fffff804`6202bbe5 : nt!CmpCommitLightWeightTransaction+0x6a
ffff9081`ea25aa50 fffff804`6202bbe5     : ffff9081`ea25ab60 ffffcd81`02eed080 00000000`00000000 00000000`00000000 : nt!NtCommitRegistryTransaction+0xbf
ffff9081`ea25aae0 00007fff`129306a4     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.