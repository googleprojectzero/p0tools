# Windows Kernel unsafe behavior in CmpUndoDeleteKeyForTrans when transactionally re-creating registry keys

Due to design-level limitations of the Windows Registry, it seems impossible to transactionally delete a registry key and then re-create it within the scope of the same transaction using the standard kernel workflows for key creation. But such a situation may realistically take place and must therefore be handled by the system. To work around this problem, there is a special internal `CmpUndoDeleteKeyForTrans` routine which, instead of constructing a key with the given name and a fresh set of properties, tries to simulate the effects of a combined delete+create operation using the old key node. Its overall logic is outlined below:

1. Ensure that the last unit-of-work (UoW) on the key's UoW list is `UoWDeleteThisKey` (i.e. the key has been transactionally deleted).
2. Iterate through the key's values and insert a new UoW of type `UoWDeleteValue` for each of them.
3. Replace the type of the key's `UoWDeleteThisKey` UoW with `UoWIsolation`, effectively cancelling the deletion of the key. Accordingly, replace the type of the parent key's `UoWDeleteChildKey` UoW with `UoWIsolation`, too.
4. Take ownership of the key's transacted value list by resetting its `KCB.TransValueCache` structure and setting the `KCB.TransValueListOwner` pointer to the address of the current transaction.

So in summary, the code reduces a pair of subsequent key deletion/creation operations to the deletion of all of its values. This may seem correct and functionally equivalent at first glance, but we have identified several issues with this approach:

1. Values are the most visible, but not the only component of a registry key that gets reset with a traditional sequence of delete+create calls. Other important key properties are its storage type, flags, class and security descriptor; none of these are re-set in accordance with the transacted create operation. This breaks the Registry API contract, as it leads to the "new" key inheriting a number of properties from the old key, while the API caller is led to believe that it successfully created a key with the new configuration.
2. The function forcibly sets the `KCB.TransValueCache` structure to `{Count = 0, List = -1}`, but doesn't free the hive cell corresponding to the previous list if it existed. This leads to a hive-based memory leak condition.
3. The function changes the UoW types of operations within an active transaction in memory, and potentially adds new UoWs to delete any existing values, but none of these modifications are reflected in the KTM log files by saving them via the `CmAddLogForAction` function. This means that whenever the system unexpectedly reboots in the middle of such a transaction, the state restored from the transaction logs will be inconsistent and will not correctly express the actual sequence of registry operations that had taken place.

Among the above problems, issue #1 seems to have the most potential for some security impact, as it directly concerns security descriptors. It is possible to develop a program which performs the following steps, all in the scope of a single transaction:

1. Creates a key with permissive access rights,
2. Deletes the key,
3. Creates the same key with restrictive access rights,
4. Writes a secret value to the key,
5. Commits the transaction.

This is what the attached proof-of-concept exploit does. It has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715). The expected outcome is that the key is only accessible by Administrators (i.e. the new security descriptor is effective):

```
C:\>reg query HKCU\TestKey
ERROR: Access is denied.

C:\>
```

The effective outcome is that the final key inherits the descriptor from its previous instance, and is readable by everyone in the system:

```
C:\>reg query HKCU\TestKey

HKEY_CURRENT_USER\TestKey
    Secret    REG_SZ    Secret data

C:\>
```

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.