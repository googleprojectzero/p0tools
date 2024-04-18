# Windows Kernel registry quota exhaustion may lead to permanent corruption of the SAM database

As previously explained in Project Zero issue #2433, there are two types of memory quotas enforced on the Windows registry:

1. A per-hive limit of 2 GiB for each of the stable/volatile storage spaces, adding up to 4 GiB total,
2. A system-wide limit of 4 GiB for the combined size of all hives actively loaded in the system.

Local attackers may very easily take up large portions of the quota by loading their own app hives and/or operating on writable keys in HKCU and even system hives. With this in mind, the first limit may be abused to fill up a specific hive and prevent other users/programs from adding any new data to it, while the second enables an attacker to globally stall all registry operations in the system, even in hives they otherwise don't have direct access to. For these reasons, it is important that highly privileged applications and services are very cautious when performing security-sensitive operations on the registry, preferably utilizing transactions to ensure the atomicity of the changes, or providing robust error handling that always restores the registry to a consistent state (the former being more reliable and easier to implement than the latter). Depending on the specific case, failure to gracefully handle errors in the middle of complex registry modifications may result in leaving it in an invalid state (e.g. only writing partial configuration) and may have significant implications for the security of the system.

The most sensitive registry hive in Windows is SAM (Security Account Manager), which stores user passwords and other account-related information. It is located in `C:\Windows\system32\config\SAM` on disk and is loaded in the registry tree under `HKLM\SAM`. Neither normal users nor even administrators have write access to it: the hive can only be manipulated indirectly through the SAM Server service implemented in `samsrv.dll` and running in the context of the LSASS process. This design works as an extra safeguard against applying breaking changes to SAM and making the system unbootable as a result.

The importance of protecting the internal consistency of SAM and the related SECURITY hive must have been clear to the developers of Windows NT in the early 1990's, as they implemented rudimentary transaction support for this purpose long before the introduction of fully-fledged KTM transactions in Windows Vista (2007) or lightweight registry transactions in Windows 10 1607 (2016). This simple transaction system is called "RXact" and according to our research, has virtually non-existent public documentation. However, it is still used to this day to protect SAM/SECURITY against corruption in the latest Windows versions. Here are some important facts about it:

- Hives that are subject to these transactions can be identified by the "RXACT" key being present in the root of the protected subtree (e.g. `HKLM\SAM\SAM\RXACT` and `HKLM\SECURITY\RXACT`).
- It is implemented in the `ntdll.dll` user-mode library. A few examples of functions being part of this interface are `RtlInitializeRXact`, `RtlStartRXact`, `RtlAddAttributeActionToRXact`, `RtlApplyRXactNoFlush` and `RtlAbortRXact`.
- It supports only two types of operations: deleting a key and setting a value.
- It can operate in one of two modes, depending on whether the hive has lazy flushing enabled or not.

The SAM hive is very unique in that it is the only one in the system with lazy flushing disabled, making its only user - SAM Server - solely responsible for deciding when to flush or discard any in-memory changes to disk. This is neatly used to achieve atomicity guarantees by being able to wholly revert the hive to a previous "checkpoint" in case any errors are encountered while committing a transaction. Let's consider the complete list of steps involved in performing a single self-contained operation on the SAM hive, such as creating a new user:

1. The RXact context is initialized via `RtlInitializeRXact`.
2. A transaction is started via `RtlStartRXact`.
3. A sequence of operations is added to the transaction via `RtlAddActionToRXact` and `RtlAddAttributeActionToRXact`.
4. The transaction is committed (in-memory) via `RtlApplyRXactNoFlush`.
5. If step #4 succeeded, the in-memory representation of the hive is flushed to disk via `NtFlushKey`.
6. If step #4 failed, the in-memory representation of the hive is restored from the file via `NtRestoreKey`, thus discarding any partial changes from the attempt to commit the transaction.

This approach seems reasonable, but we have identified two major problems that make it ineffective and can enable a local attacker to interfere with ongoing administrative operations on SAM and corrupt the database. These issues are as follows:

- The architecture relies on the fact that only the SAM Server can flush the SAM hive, and thus create an internally consistent snapshot whenever it is safe to do so. But in fact, the root `HKLM\SAM` key grants `KEY_READ` access to the "Users" group, so any local user can open a handle to the hive, and the `NtFlushKey` syscall doesn't require any special permissions at all. Consequently, anyone can flush the SAM hive at any time, including in the middle of committing a transaction when the hive is in a transitional state. For example, when a malicious user runs a process that flushes SAM in an infinite loop at the same time as step #4 executes and fails at some point, then the `NtRestoreKey` call in step #6 will restore the hive to the state it was in during the last `NtFlushKey` call (which could be a partially committed state), and not to the original state from before the transaction.
- If committing a complex transaction fails mid-way in step #4 due to the global 4 GiB system-wide quota being exhausted, then the rollback call to `NtRestoreKey` in step #6 will also most likely fail with a `STATUS_INSUFFICIENT_RESOURCES` error because it also tries to allocate memory from the same exhausted 4 GiB pool. This results in an emergency shutdown of the SAM Server (stopping any future interactions with it, e.g. preventing users from logging in), and may also leave the in-memory SAM database in an inconsistent state. An attacker could then manually flush the hive to disk, making the corruption persistent and potentially unrecoverable without a complete reinstall of the operating system.

Let's consider an example of creating a new user in the system by an administrator. If we use Process Monitor in a test Windows installation with filters set to show writes to the SAM hive, and use the following command from an elevated prompt:

```
C:\>net user user2 password /add
```

then we can observe that the procedure consists of 20+ registry operations, with some of them being:

- Reserving the user name by creating a `HKLM\SAM\SAM\Domains\Accounts\Users\Names\user2` key and writing the user ID to its default value,
- Reserving the user ID by creating the `HKLM\SAM\SAM\Domains\Account\Users\<ID>` key and writing credentials / various configuration data to its values,
- Adding the user to relevant groups by creating keys and setting values inside `HKLM\SAM\SAM\Domains\Builtin\Aliases`.

In our testing, there are typically three points in time when the global registry quota is claimed in the process, all of them as a result of calling `CmpAllocate` (which then calls `CmpClaimGlobalQuota`) in `CmpAddSubKeyToList` when creating new keys in SAM. As a side note, the quota is usually not claimed when setting values because they are allocated from the free space in existing hive bins that are already accounted for in the claimed quota. Furthermore, we see no reason why `CmpAddSubKeyToList` uses `CmpAllocate` instead of just `ExAllocatePoolWithTag` for a temporary buffer containing the key name that is then immediately freed in the same function. But in the current implementation, there are three subsequent `CmpAllocate` -> `CmpClaimGlobalQuota` calls:

1. `CmpClaimGlobalQuota(10)` -> corresponds to the length of a wide-char representation of "user2"
2. `CmpClaimGlobalQuota(16)` -> corresponds to the length of a wide-char representation of the new user ID formatted as a hexdecimal 32-bit number, e.g. "000003ED".
3. `CmpClaimGlobalQuota(16)` -> same as above.

So if the global `CmpGlobalQuotaUsed` variable is set to 0xFFFFFFF2 (which can be easily achieved by a local attacker) at the beginning of the process, then the first key creation request will succeed but the second one will fail, thus aborting in the middle of the user creation process.

Below is a specific list of steps that can be used to reproduce the problem (we tested on Windows 11 22H2, November 2023 update, build 22621.2715):

1. Start the test system, login as administrator, attach WinDbg to it as a kernel debugger.
2. For more visibility, start Process Monitor and set it to display writes to SAM (`RegCreateKey`, `RegSetValue`, `RegFlushKey`, `RegRestoreKey` operations).
3. In the debugger, list all hives loaded in the system using the `!reg hivelist` command, find SAM and write down its `HiveAddr`.
4. Set a conditional breakpoint on the internal `CmSetValueKey` function to break whenever a value is written to SAM, using the following command: `bp /w "((_CM_KEY_BODY*)@rcx)->KeyControlBlock->KeyHive == 0x<SAM_HIVE_ADDR>" CmSetValueKey`.
5. In an elevated command prompt, type `net user user2 password /add` and hit enter,
6. The breakpoint at `CmSetValueKey` should trigger in WinDbg. 
7. Write 0xFFFFFFF2 to `CmpGlobalQuotaUsed` by using the following command: `ed CmpGlobalQuotaUsed fffffff2`
8. Remove the breakpoint: `bc 0`, and continue system execution: `g`.

The expected outcome is that the user creation fails with the following error:

```
C:\>net user user2 password /add
System error 1450 has occurred.

Insufficient system resources exist to complete the requested service.


C:\>
```

In Process Monitor, we can see that the first six `RegCreateKey`/`RegSetValue` operations succeeded, having managed to create the user name and add the new user to the "Users" group. But then the key creation of `HKLM\SAM\SAM\Domains\Account\Users\000003ED` failed with `INSUFFICIENT RESOURCES`, and immediately after, the `RegRestoreKey` operation (which was meant to revert the transaction) failed with the same error as well. At this point, the SAM Server has shut down and doesn't accept any new requests. For example if we try to re-run the same command again, we'll get:

```
C:\>net user user2 password /add
This operation is only allowed on the primary domain controller of the domain.

More help is available by typing NET HELPMSG 2226.


C:\>
```

The in-memory SAM database is also corrupt at this stage. Anyone in the system can flush this bad state to disk and make it persistent - an example of how to achieve this is shown in the attached `FlushSam` program. If we run it and then reboot the test VM, the SAM Server is up again and it is possible to log in, but the inconsistent state becomes apparent as soon as the administrator tries to manage user accounts. The "user2" account doesn't exist, but it does show up in the user list as the name has been successfully claimed:

```
C:\>net user

User accounts for \\WIN11

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
test                     user                     user2
WDAGUtilityAccount
The command completed successfully.


C:\>
```

Moreover, in the partially committed state of SAM, the new user's SID has been added to the Users group, but the SID itself hasn't been fully reserved. So when an administrator attempts to create a new user, LSASS tries to re-use the same SID, but it sees that the SID is already part of an existing group and rejects the request:

```
C:\>net user some_other_username password /add
The user already belongs to this group.

More help is available by typing NET HELPMSG 2236.


C:\>
```

This illustrates that the SAM database has been permanently damaged, making it impossible to perform standard administrative tasks in the system. We haven't further investigated the exploitability of this issue for infoleak/privilege escalation potential.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.