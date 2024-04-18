# Windows overly permissive access rights set on the HKCU\Software\Microsoft\Input\TypingInsights registry key

We have found that on a default installation of Windows 11 22H2 (November 2023 update, build 22621.2715), there is a `HKCU\Software\Microsoft\Input\TypingInsights` key with a security descriptor allowing much broader access than expected. Specifically, it has the following ACL:

```
PS C:\> Get-Acl -Path HKCU:\Software\Microsoft\Input\TypingInsights | Format-List

Path   : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Input\TypingInsights
Owner  : WIN11\user
Group  : WIN11\None
Access : NT AUTHORITY\Authenticated Users Allow  SetValue, CreateSubKey, ReadKey
         NT AUTHORITY\SYSTEM Allow  SetValue, CreateSubKey, ReadKey
         BUILTIN\Users Allow  SetValue, CreateSubKey, ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  SetValue, CreateSubKey, ReadKey
```

This grants all users in the system read and write access to the specific key, while generally all other keys inside HKCU only grant access to the corresponding user and administrators, as the data in the hive is indeed supposed to be private to that user. We have found that the permissive rights are set when creating the key in the `UserInsights::SetRegistryValue` method, which is found in several system DLLs:

- `mshtml.dll`
- `edgehtml.dll`
- `InputService.dll`
- `msftedit.dll`
- `SettingsHandlers_InputPersonalization.dll`

The specific DACL string being used during the key creation process is:

```
D:(A;CIOI;KRKW;;;SY)(A;CIOI;KRKW;;;BU)(A;CIOI;KRKW;;;AU)(A;CIOI;KRKW;;;AC)
```

This doesn't seem to have a huge security impact on the surface, as the `TypingInsights` key doesn't store particularly sensitive information. In itself, it could likely only be abused to either disclose a user's typing insights numbers, or modify those statistics. However, this behavior also has some indirect security implications:

- A malicious local user can persistently exhaust the maximum 2 GiB space of another user's hive by creating many long values in the `TypingInsights` key, thus preventing other legitimate applications run by that user from effectively operating on HKCU. Furthermore, due to the global 4 GiB quota enforced on the total registry memory consumption in Windows, if other large hives are loaded in the system, then inflating another user's hive may prevent them from being able to log in to their account in the future.
- Similarly, permissive rights set on a key in HKCU also enable access to the corresponding key via all differencing hives that are mounted on top of it, i.e. the hives under `\Registry\WC\Silo\<SID>user_sid` loaded on behalf of programs running in an Application Silo. This again makes it possible to fill them up to their maximum capacity and thus prevent the applications from running correctly.
- Lastly, world-writable keys present in HKCU may create a convenient foothold for exploiting more serious, registry-specific vulnerabilities. By opening a key with the rights to create values and subkeys, the specific hive becomes open to a significant attack surface related to symbolic links, registry virtualization, transactions, layered keys and so on. We believe it is a worthwhile defense-in-depth approach to keep the user hives strictly protected, to prevent unauthorized local users from being able to open writable handles to others' HKCUs and from being able to execute potential cross-user attacks as a result.

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.