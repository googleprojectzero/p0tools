# Windows Kernel security descriptor linked list confusion in CmpLightWeightPrepareSetSecDescUoW

The implementation of the so-called lightweight registry transactions in the Windows kernel follows a failsafe design pattern, by splitting the "commit" action into two phases:

1. The Prepare phase, responsible for executing all of the sub-operations that may plausibly fail while preparing each unit-of-work (UoW) for being committed, i.e. by pre-allocating relevant cells in the hive, marking existing cells as dirty, allocating helper objects from the kernel pools, adding/removing items to/from various lists, and so on. If any error occurs at this stage, the whole transaction is aborted, which can be safely achieved since none of the operations performed in the Prepare phase have any persistent effect on the global view of the registry.
2. The Commit phase, which takes all of the data structures pre-arranged in step 1 and installs them in the global view of the registry. It is impossible for this phase to fail as it doesn't perform any error-prone operations, only simple memory manipulation.

This design delivers on the promise of fully atomic transactions, and isn't affected by the same problems that were reported in Project Zero issue #2433 ("Windows Kernel KTM registry transactions may have non-atomic outcomes"). Internally, every of the seven major UoW types has two handler functions, one for each phase, with their names starting with `CmpLightWeightPrepare[...]` and `CmpLightWeightCommit[...]` respectively. For example, if a program transactionally creates a key, sets its security descriptor and sets a new value within it, then tries to commit the transaction, the following kernel functions get called consecutively:

1. `CmpLightWeightPrepareAddKeyUoW`
2. `CmpLightWeightPrepareSetSecDescUoW`
3. `CmpLightWeightPrepareSetValueKeyUoW`
4. `CmpLightWeightCommitAddKeyUoW`
5. `CmpLightWeightCommitSetSecDescUoW`
6. `CmpLightWeightCommitSetValueKeyUoW`

As we can see, all "Prepare" functions are executed in the order in which the UoWs were added to the transaction, followed by the execution of the corresponding "Commit" procedures. The reliability of this scheme comes with some challenges, though - the implementation of each basic operation is now split into two parts, which operate on slightly different states of the registry. In between each pair of Prepare/Commit functions, the globally visible state may be modified by Commit functions associated with other UoWs in the transaction. Because of this, each Prepare handler must either correctly foresee the state of the registry during the Commit phase, or be able to prove that the relevant state can't change in the meantime. The problem described in this report is the fact that `CmpLightWeightPrepareSetSecDescUoW` fails to do so correctly.

Let's note some context first:

- All security descriptors in the stable storage of a hive are connected in a single linked list via the `_CM_KEY_SECURITY.{Flink,Blink}` cell indexes.
- Whenever a new security descriptor is assigned to a key, it is possible that the old descriptor will get freed and unlinked from the list (if this was the last reference to it).
- Writing to any cell in the hive must be preceded by marking it as dirty, to keep the in-memory and on-disk representation of the hive in sync. This is achieved by calling the `HvpMarkCellDirty` function, which may potentially fail.

Considering the above, it becomes easier to understand the following snippet of the `CmpLightWeightPrepareSetSecDescUoW` function presented in C-like pseudo code:

```c
NTSTATUS CmpLightWeightPrepareSetSecDescUoW(_CM_KCB_UOW *uow) {

  [...]

  _CM_KEY_NODE *KeyNode = Hive->GetCellRoutine(uow->KeyControlBlock->KeyCell);
  _CM_KEY_SECURITY *SecurityNode = Hive->GetCellRoutine(KeyNode->Security);

  if (!HvpMarkCellDirty(Hive, KeyNode->Security) ||
      !HvpMarkCellDirty(Hive, SecurityNode->Flink) ||
      !HvpMarkCellDirty(Hive, SecurityNode->Blink)) {
    return STATUS_NO_LOG_SPACE;
  }

  [...]

}
```

What is effectively happening here is that the function dirties the key's current security descriptor, and also preemptively dirties the forward/backward links in case the descriptor gets freed and unlinked from the list (thus triggering writes to the adjacent elements). This seems like a sensible thing to do, but it is only correct if there is exactly one `UoWSetSecurityDescriptor` operation on a given key within a transaction. If there are more, then the Prepare handler dirties the wrong cells in the 2nd and next iterations: instead of dirtying the security descriptor that will have been effective during the Commit phase of the given UoW, it keeps dirtying the old security descriptor of the key. Let's imagine an example with four security descriptors present in a hive and linked together:

```
        +----------------+     +----------------+     +----------------+     +----------------+     
... <-- | Security       | <-- | Security       | <-- | Security       | <-- | Security       | <-- ...
... --> | Descriptor #1  | --> | Descriptor #2  | --> | Descriptor #3  | --> | Descriptor #4  | --> ...
        +----------------+     +----------------+     +----------------+     +----------------+
```

Let's assume that initially, there is a test key using Security Descriptor #1. Next, we transactionally change its security to SD #2, then to SD #4, and commit the transaction. As a result, both calls to `CmpLightWeightPrepareSetSecDescUoW` result in marking SD #1, SD #2, and some unknown descriptor prior to SD #1 as dirty. Instead, the correct behavior would be to dirty SD #2 (current security), SD #1 and SD #3 (its `Blink`/`Flink`) in the second execution of `CmpLightWeightPrepareSetSecDescUoW`. Otherwise, if the second execution of `CmpLightWeightCommitSetSecDescUoW` happens to free SD #2, then it will try to modify the `Blink` field of SD #3 without having marked it as dirty.

One important detail is that in such a scenario, it is only possible for SD #2 to be freed if its `ReferenceCount=1`, i.e. our test key has been (for a very short time) its only user. One way this could happen is if SD #2 didn't exist in the hive before, and it was only allocated for the purpose of assigning it to our test key. But if that was the case, then SD #1 and most importantly SD #3 would have been marked as dirty when inserting SD #2 into the list, so there would be no issue. The only other circumstance in which SD #2 would be freed in the second call to `CmpLightWeightCommitSetSecDescUoW` while not already having its adjacent descriptors marked as dirty is if it was already present in the hive but with `ReferenceCount=0` (i.e. effectively unused). This is an abnormal state that won't organically occur, because every time a security descriptor becomes unused, it is immediately freed by the kernel. However, it turns out that it is possible to induce such a state by abusing a certain family of minor registry bugs/quirks.

Specifically, if one manages to create a key in the registry with some unusual properties that will be accepted by the key creation codeflow, but will make the key seem invisible or invalid to the `CmpCheckRegistry`/`CmpCheckKey` functions while loading the hive after a reboot, then the `CmpCheckAndFixSecurityCellsRefcount` function will decrement the descriptor's `ReferenceCount` accordingly, but won't free it even if it becomes zero. One example of such a situation is when a stable key is created under a volatile one; while theoretically impossible, we have found ways to achieve this in the past (e.g. Project Zero issue #2375, section "Creation of stable subkeys under volatile keys"). If this happens, the key holds a valid reference to its security descriptor for as long as it lives in the active hive, but upon reboot, the kernel loses sight of the key so the reference is dropped.

Another option, which is used by our proof-of-concept exploit, is via the discrepancy in the behavior of `CmpCheckKey` vs. `NtRenameKey`. When loading a hive, the system rejects keys that start with the nul character (`\0`), but the rename syscall allows to assign such a name to existing keys. We are not aware of any significant security implications of this behavior, but similarly to stable-under-volatile keys, it may prove potentially useful as a technique facilitating exploitation of other bugs.

So if everything goes according to plan, an attacker can abuse the bug to get the kernel to write to a cell without marking it as dirty first. What is the security impact of this primitive? This depends largely on the internals of the dirtying/flushing mechanism. If the only role of `HvpMarkCellDirty` was to record which portions of the hive need to be soon flushed to disk, this could potentially lead to de-synchronizing the in-memory and on-disk representation of system hives and corrupting them, enabling an elevation of privilege. However, according to our testing, hive pages are mapped as read-only unless marked dirty (perhaps as a troubleshooting and/or defense-in-depth mechanism), so an attempt to write to such a cell immediately leads to a kernel crash due to an unhandled exception.

Attached is a proof-of-concept exploit that has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715). Its logic is split into two stages separated by a system reboot. The first stage consists of the following steps:

1. Sets up a test key structure under the world-writable `HKLM\Software\Microsoft\DRM` key, which also results in adding four unique security descriptors to the hive's list. The aim is to allocate each descriptor from a different memory page, which is achieved by adding filler values in between the creation of consecutive keys.
2. Abuses the `NtRenameKey` behavior to change the `TestKey2` name to `\0`, which will effectively remove the key on the next reboot and reset its security descriptor to `ReferenceCount=0` while keeping it alive on the list.
3. Flushes all pending changes in `HKLM\Software` to disk.
4. Asks the user to restart the system.

Following a reboot, the exploit executes the second stage:

5. Opens the `HKLM\Software\Microsoft\DRM\TestKey1` key transactionally.
6. Sets SD #2 on the key.
7. Sets SD #4 on the key.
8. Flushes all pending changes in `HKLM\Software` to disk, to clear any dirty bits currently set in the hive.
9. Commits the transaction, which triggers the bug and crashes while trying to write to a read-only cell in `CmpRemoveSecurityCellList`.

An example crash log is as follows:

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
Arg2: fffff80714755da8, Address of the instruction which caused the bugcheck
Arg3: ffff83833e9a9e30, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

[...]

CONTEXT:  ffff83833e9a9e30 -- (.cxr 0xffff83833e9a9e30)
rax=0000000000a0b370 rbx=ffffc5024121b000 rcx=ffffc5024121b000
rdx=ffff83833e9aa8b0 rsi=000001c2b1f7c374 rdi=000001c2b59e2b04
rip=fffff80714755da8 rsp=ffff83833e9aa850 rbp=ffff83833e9aa870
 r8=ffff83833e9aa8bc  r9=0000000000000095 r10=ffffc5024121b000
r11=ffff83833e9aa958 r12=0000000000000000 r13=0000000000000000
r14=000001c2b5a0649c r15=0000000004471b00
iopl=0         nv up ei pl nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050206
nt!CmpRemoveSecurityCellList+0xb8:
fffff807`14755da8 41894604        mov     dword ptr [r14+4],eax ds:002b:000001c2`b5a064a0=04471b00
Resetting default scope

PROCESS_NAME:  Registry

STACK_TEXT:  
ffff8383`3e9aa850 fffff807`14755cb2     : 00000001`04471b00 ffffc502`4121b000 00000001`00a0b370 00000001`04495498 : nt!CmpRemoveSecurityCellList+0xb8
ffff8383`3e9aa8a0 fffff807`14e265a4     : 00000001`04471b00 ffffc502`4121b000 ffff8383`3e9aa998 ffff8383`3e9aa940 : nt!CmpDereferenceSecurityNode+0x6e
ffff8383`3e9aa8d0 fffff807`14e1a8c8     : 00000001`017fca38 00000000`00000001 ffff8383`3e9aa998 ffff8383`3e9aa9e0 : nt!CmpLightWeightCommitSetSecDescUoW+0x64
ffff8383`3e9aa920 fffff807`14e1a529     : ffffc502`47e97700 ffff8383`3e9aa9e0 ffff8383`3e9aaa20 fffff807`14e1a6f7 : nt!CmpProcessLightWeightUOW+0x1ac
ffff8383`3e9aa960 fffff807`14e1a3e7     : ffffc502`47809fe0 00000000`00000000 00000000`00000000 fffff807`14ef32de : nt!CmpCommitPreparedLightWeightTransaction+0xd5
ffff8383`3e9aaa00 fffff807`14e0b1ef     : 00000000`00000000 00000000`00000000 ffff8383`3e9aab60 00000000`00000000 : nt!CmpCommitLightWeightTransaction+0x10b
ffff8383`3e9aaa50 fffff807`1482b6e5     : 00000000`000000c8 ffffd68c`dc010080 00000000`00000000 00000000`00000000 : nt!NtCommitRegistryTransaction+0xbf
ffff8383`3e9aaae0 00007ffc`3ee506a4     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x25
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.