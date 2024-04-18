# Windows Kernel enforcement of registry app hive security is inconsistent with documentation

Application hives ("app hives" in short) are a special type of Windows registry hives that can be loaded by programs without any special privileges in the system. They are loaded using a dedicated `RegLoadAppKey` API function, and the newly mounted hives are private to the loading process and not globally visible in the registry tree. Another special property of app hives is that they are supposed to only contain a single security descriptor, and the descriptor is generally expected to grant wide access to the user accessing the hive. 

These expectations are evidenced by several remarks in official MSDN articles, for example:

- Documentation of the [RegLoadAppKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeya) function claims:

```
All keys inside the hive must have the same security descriptor, otherwise the function will fail. This security descriptor must grant the caller the access specified by the samDesired parameter or the function will fail.
```

- The [Filtering Registry Operations on Application Hives](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-operations-on-application-hives) article states:

```
In contrast to other types of registry hives, for which each key is secured with its own security descriptor, the security of an application hive is based on the hive file's security descriptor. This means that: [...] An entity that is successful in loading the hive can modify the entire hive.
```

These statements could be true if all app hives had been originally created with a `RegLoadAppKey()` call on a non-existent file, and later operated on solely by the Windows API. However, programs may invoke `RegLoadAppKey` against arbitrary hives created in other ways, and neither the user-mode API nor the underlying kernel implementation strictly enforce the requirements related to the security descriptors. Specifically:

1. No limit on the number of security descriptors is imposed while loading an app hive, so in extreme cases every key could be assigned a different, unique security descriptor.
2. Access specified via the `samDesired` parameter to `RegLoadAppKey` is only checked against the root of the hive, when calling `ObOpenObjectByPointer` in `CmLoadDifferencingKey`.
3. If there is more than one security descriptor in the hive, then the kernel makes sure that the current user has at least `KEY_READ` access to each of them by calling `CmpCheckSecurityCellAccess` in a loop in `CmpValidateHiveSecurityDescriptors`.

The above logic is inconsistent with documentation, especially point #1 directly contradicts MSDN and further contributes to the problem with point #2 (i.e. if it was guaranteed that there is only one security descriptor, performing a check against the root of the hive would be effective for the whole hive). While we don't see any direct security implications of this behavior, it could open the possibility to exploit potential future security bugs related to security descriptors by unprivileged users, so it might be worth addressing it as a defense-in-depth measure. Hence, we are reporting it to MSRC for their assessment without a disclosure deadline.

Attached is a proof-of-concept hive file, and a simple test program that loads it as an app hive with the `KEY_ALL_ACCESS` access mask (and then expects to fail to open a subkey with `KEY_WRITE` access). The hive file consists of a root key and two subkeys, each with a different security descriptor:

- The root key grants `KEY_ALL_ACCESS` to Everyone.
- `SubKey1` grants `KEY_READ` to Everyone.
- `SubKey2` grants `KEY_READ` to Authenticated Users.

The fact that it is possible to load such an app hive demonstrates that the security descriptor limit is not enforced, that the `samDesired` mask is not checked against every security descriptor in the hive, and that an app hive may contain keys that the loading process doesn't have write access to. We have successfully confirmed this behavior on Windows 11 22H2 (January 2024 update, build 10.0.22621.3007).

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.