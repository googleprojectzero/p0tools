# Windows Kernel VRegDriver registry callback doesn't handle key renaming

VRegDriver is a small module compiled into the core Windows kernel image (`ntoskrnl.exe`) that implements registry namespace redirection as part of the larger registry containerization feature introduced in Windows 10 1607. It is used, for example, by applications running in the AppContainer (so-called app silos) and Docker containers (server silos). It achieves its goals by registering a registry callback called `VrpRegistryCallback`, which checks if the given key is subject to containerization, and if so, passes execution to one of the specialized handlers corresponding to the registry operation (`VrpPreQueryKeyName`, `VrpPostEnumerateKey`, `VrpPreOpenOrCreate`, etc.). For every newly opened virtualized key, the `VrpPostOpenOrCreate` handler allocates a key-specific context structure with `VrpAllocateKeyContext` and saves the full path of the real key that the virtualized key is emulating. This cached path may later become useful when opening further subkeys relative to this one, or when intercepting a request to query the name of a key in `VrpPreQueryKeyName`.

For example, the root of a differencing hive mounted at:

```
\REGISTRY\WC\SILO7AF8C58B-2103-498E-81EB-47918ADF6CB5USER_CLASSES
```

may have the following real path stored in the VRegDriver context object:

```
\Registry\User\S-1-5-21-123456789-123456789-123456789-1002_Classes
```

The issue described in this report is the fact that the registry callback caches the key path, but doesn't update it when a key is renamed (by handling the `RegNtPostRenameKey` callback type). As a result, after a successful rename, the key context may contain stale information. This, in turn, may have the following consequences:

1. Querying the key name via `NtQueryObject(ObjectNameInformation)` may return incorrect data, pointing at non-existent or incorrect registry paths.

2. The behavior may allow operations on the renamed key that wouldn't be otherwise possible if the key was opened through the new name directly. For example, on Windows 11, there is a default list of registry paths excluded from registry isolation specified in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AppModel\RegistryWriteVirtualization\ExcludedKeys`. Whenever such a path is opened, the kernel grants the process direct access to it rather than redirecting the operation to the corresponding differencing hive under `\Registry\WC`. One of the excluded keys is `HKEY_CURRENT_USER\Environment`, so if a program running in an AppSilo opens `HKCU\Environment` and then renames it to something else, it has the ability to create an arbitrary key tree in the system-wide HKCU hive outside of the container, something it wouldn't be normally allowed to do.

The second condition can be reproduced with the attached proof-of-concept exploit. It performs the following steps:

1. Starts the Notepad process, which runs inside an app silo and is subject to containerized registry.
2. Finds a virtualized registry key handle owned by Notepad pointing at HKCU, and duplicates it to the current process.
3. Opens the Environment key relative to the root of the differencing hive. Because the key is excluded from virtualization, this returns a handle to the real underlying `HKCU\Environment` key.
4. Renames the key to `TestKey` and sets a REG_SZ value inside it to demonstrate the ability to persistently save data in the host's HKCU hive.

We have successfully reproduced the behavior on Windows 11 22H2 (January 2024 update, build 10.0.22621.3007). The specific security impact of this issue (if any) is unclear, so we are reporting it to MSRC for their assessment without a disclosure deadline.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.