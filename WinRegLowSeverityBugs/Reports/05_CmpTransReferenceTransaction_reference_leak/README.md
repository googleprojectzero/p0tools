# Windows Kernel lightweight transaction reference leak in CmpTransReferenceTransaction

The internal Windows kernel `CmpTransReferenceTransaction` function is used to reference two kinds of registry transaction objects: KTM and lightweight transactions, distinguished by the least significant bit of the address. If we omit KTM-related code (which is not relevant to this report), then the pseudo-code for handling lightweight transactions looks as follows:

```c
NTSTATUS CmpTransReferenceTransaction(_CM_LIGHTWEIGHT_TRANS_OBJECT *Trans) {
  ObfReferenceObject(Trans);
  return Trans->State != LIGHT_TRANS_ACTIVE ? STATUS_TRANSACTION_NOT_ACTIVE : STATUS_SUCCESS;
}
```

The `_CM_LIGHTWEIGHT_TRANS_OBJECT` structure and the `LIGHT_TRANS_ACTIVE` constant are not part of the public symbols but instead are my custom, reverse-engineered names. As we can see in the short snippet, the transaction object is referenced unconditionally, but if it turns out not to be active, a `STATUS_TRANSACTION_NOT_ACTIVE` status is returned without dereferencing the object back. And since this is an error code, the higher-level callers assume that referencing the transaction failed and there is no need to dereference it to restore it to the previous state. The result is a reference count leak, which leads to a memory leak because the refcount never drops back to zero and the object never gets freed. As far as we can tell, the security impact of the bug is limited, because the reference count is protected against integer overflows, and it is a 64-bit integer on modern systems anyway. The worst that could probably happen is a local DoS after an attacker references an object 2^32 times on a x86 system, and `ObfReferenceObject` detects the integer overflow and generates a `REFERENCE_BY_POINTER` bugcheck.

Attached is a proof-of-concept exploit to trigger a single reference leak, which has been successfully tested on Windows 11 22H2 (November 2023 update, build 22621.2715).

This report outlines findings that fall outside of Project Zero's standard 90-day disclosure policy due to their unclear or low security impact. While we strive to assess security issues accurately, if you suspect anything in this report poses a significant risk, please contact us immediately to request a 90-day disclosure deadline. Please note that reports without a disclosure deadline may be discussed or referenced publicly in the future. We will make an effort to inform you in advance if this occurs.