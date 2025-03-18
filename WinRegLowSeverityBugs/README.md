# Microsoft Windows Registry Low/Unclear Severity Bugs

This repository contains the descriptions and proof-of-concept exploits of 21 issues with low or unclear security impact found in the Windows Registry. They were reported to Microsoft between November 2023 and February 2025. Six of them were fixed by the vendor in the March 2024 Patch Tuesday, while the other fifteen were closed as WontFix/vNext. The bugs were identified during my registry research in 2022-2025, alongside the [42 reports](https://project-zero.issues.chromium.org/issues?q=customfield1352808:Microsoft%20customfield1352754:mjurczyk%20created%3E2022-05-01%20created%3C2024-12-31) filed in the Project Zero bug tracker with a 90-day disclosure deadline.

For more information about the research, please see the blog post series starting with [The Windows Registry Adventure #1: Introduction and research results](https://googleprojectzero.blogspot.com/2024/04/the-windows-registry-adventure-1.html), as well as several conference talks I have given on the subject:

* [Exploring the Windows Registry as a powerful LPE attack surface](https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/) (BlueHat Redmond 2023)
* [Practical Exploitation of Registry Vulnerabilities in the Windows Kernel](https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/) (OffensiveCon 2024)
* [Windows Registry Deja Vu: The Return of Confused Deputies](https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/) (CONFidence 2024)
* [Peeling Back the Windows Registry Layers: A Bug Hunter’s Expedition](https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/) (REcon 2024)

The issues are summarized in the table below:

ID|Title|Status|CVE
-----|-----|-----|-----
1|[Windows Kernel out-of-bounds read of key node security in CmpValidateHiveSecurityDescriptors when loading corrupted hives](Reports/01\_Key\_node\_Security\_OOB\_read)|Fixed in March 2024|CVE-2024-26174
2|[Windows Kernel out-of-bounds read when validating symbolic links in CmpCheckValueList](Reports/02\_SymbolicLinkValue\_OOB\_read)|Fixed in March 2024|CVE-2024-26176
3|[Windows Kernel pool-based buffer overflow when parsing deeply nested key paths in CmpComputeComponentHashes](Reports/03\_CmpComputeComponentHashes\_nested\_path\_overflow)|WontFix/vNext|-
4|[Windows Kernel allows the creation of stable subkeys under volatile keys via registry transactions](Reports/04\_Transacted\_stable\_under\_volatile\_keys)|Fixed in March 2024|CVE-2024-26173
5|[Windows Kernel lightweight transaction reference leak in CmpTransReferenceTransaction](Reports/05\_CmpTransReferenceTransaction\_reference\_leak)|WontFix/vNext|-
6|[Windows Kernel pool-based out-of-bounds read in CmpRmReDoPhase when restoring registry transaction logs](Reports/06\_CmpRmReDoPhase\_transaction\_GUID\_OOB\_read)|WontFix/vNext|-
7|[Windows Kernel NULL pointer dereference in CmpLightWeightPrepareSetSecDescUoW](Reports/07\_CmpLightWeightPrepareSetSecDescUoW\_NULL\_pointer\_dereference)|WontFix/vNext|-
8|[Windows Kernel infinite loop in CmpDoReOpenTransKey when recovering a corrupted transaction log](Reports/08\_CmpDoReOpenTransKey\_infinite\_path\_splitting\_loop)|vNext (fixed in Insider Preview)|-
9|[Windows Kernel NULL pointer dereference in NtDeleteValueKey](Reports/09\_NtDeleteValueKey\_NULL\_pointer\_dereference)|WontFix|-
10|[Windows Kernel user-triggerable crash in CmpKeySecurityIncrementReferenceCount via unreferenced security descriptors](Reports/10\_CmpKeySecurityIncrementReferenceCount\_zero\_refcount\_crash)|WontFix/vNext|-
11|[Windows Kernel memory leak in VrpPostOpenOrCreate when propagating error conditions](Reports/11\_VrpPostOpenOrCreate\_error\_handling\_memory\_leak)|WontFix/vNext|-
12|[Windows Kernel unsafe behavior in CmpUndoDeleteKeyForTrans when transactionally re-creating registry keys](Reports/12\_CmpUndoDeleteKeyForTrans\_unsafe\_behavior)|Fixed in March 2024|CVE-2024-26177
13|[Windows Kernel security descriptor linked list confusion in CmpLightWeightPrepareSetSecDescUoW](Reports/13\_CmpLightWeightPrepareSetSecDescUoW\_security\_list\_confusion)|Fixed in March 2024|CVE-2024-26178
14|[Windows overly permissive access rights set on the HKCU\Software\Microsoft\Input\TypingInsights registry key](Reports/14\_HKCU\_TypingInsights\_permissive\_access\_rights)|WontFix/vNext|-
15|[Windows Kernel registry quota exhaustion may lead to permanent corruption of the SAM database](Reports/15\_Registry\_quota\_exhausted\_SAM\_corruption)|Fixed in March 2024|CVE-2024-26181
16|[Windows Kernel integer overflow of big data chunk count when handling very long registry values](Reports/16\_Registry\_value\_big\_data\_count\_overflow)|WontFix/vNext|-
17|[Windows Kernel fails to correctly unlink KCBs from discard replace context in CmpCleanupDiscardReplacePost](Reports/17\_CmpCleanupDiscardReplacePost\_bad\_KCB\_unlinking)|WontFix/vNext|-
18|[Windows Kernel returns success in an error path of HvCheckBin during registry hive sanitization](Reports/18\_HvCheckBin\_incorrect\_return\_value)|WontFix/vNext|-
19|[Windows Kernel VRegDriver registry callback doesn't handle key renaming](Reports/19\_VrpRegistryCallback\_unhandled\_key\_rename)|WontFix/vNext|-
20|[Windows Kernel enforcement of registry app hive security is inconsistent with documentation](Reports/20\_App\_hive\_security\_inconsistencies)|WontFix/vNext|-
21|[Windows Kernel out-of-bounds reads and other issues in applockerfltr!SmpRegistryCallback](Reports/21\_Applockerfltr\_callback\_OOB_read)|WontFix/vNext|-
