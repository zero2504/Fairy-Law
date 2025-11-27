# Fairy-Law  


### **Fairy Law – Abusing `MicrosoftSignedOnly` to Impair EDR**


> **Full technical report available on the Orange Cyberdefense Blog.**  
> [(Link for the technical report)](https://www.orangecyberdefense.com/global/blog/cybersecurity/fairy-law)

<img width="700" height="700" alt="FairyLaw" src="https://github.com/user-attachments/assets/93613a97-e654-452c-b0e6-fd3a010ae46c" />


---

## Overview

Endpoint Detection & Response (EDR) solutions typically combine kernel-mode components with user-mode components such as monitoring modules, support libraries, and telemetry collectors. These user-mode components are often delivered as regular DLLs signed by the vendor or a third-party CA.

Windows provides a mitigation policy called `MicrosoftSignedOnly`, which enforces that a process may only load DLLs that are signed by Microsoft. When this policy is enabled system-wide, the operating system rejects all libraries that are not Microsoft-signed. This includes EDR components, even if they are properly signed by the vendor. As a result, many EDR agents cannot initialize and fail completely during startup after reboot.


---

## Why the Name “Fairy Law”

The technique name “Fairy Law” originates from the spell in the anime *Fairy Tail*. In the series, the spell affects only those the caster recognises as enemies and leaves allies unharmed.

This reflects how `MicrosoftSignedOnly` behaves. Windows treats Microsoft-signed binaries as trusted allies, while all other binaries, including legitimate vendor DLLs, are treated as hostile and are prevented from loading. 
The system itself decides what is allowed to run and rejects everything else instantly.


---

## Core Idea “Fairy Law”

The technique enables the `MicrosoftSignedOnly` policy globally by modifying:

```c
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\MitigationOptions
```

After reboot, Windows enforces the following rules:

- Only DLLs signed by Microsoft may be loaded
- Vendor-signed and third-party-signed DLLs cannot be loaded
- EDR agents depending on these DLLs fail to start
- User-mode telemetry, monitoring modules, and anti-tamper systems do not initialize
- The policy is applied once during kernel **Phase 0** and cannot be refreshed at runtime

This leads to complete operational failure of many EDR solutions.


---

## Technical Notes

`MitigationOptions` is evaluated once during kernel **Phase 0** before any user-mode process exists. Any change made later is ignored until the next reboot. Modifying this registry area requires administrator privileges followed by a restart.

Powershell example:
```powershell
Set-ProcessMitigation -System -Enable MicrosoftSignedOnly
```

The same configuration can be applied programmatically by writing the corresponding 20-byte bitmask using `RegSetValueExA`.


---
## Limitations for Attackers

While this mitigation unintentionally disables several security products, it also limits attackers by blocking:

- Custom DLL injection
- Reflective DLL loading

Attackers must rely instead on techniques that do not require DLL loading, such as in-memory shellcode, living-off-the-land binaries, or misuse of legitimate Microsoft-signed components.


---
## Additional Observation

Enforcing `MicrosoftSignedOnly` globally affects not only security products but also numerous legitimate applications. Many third-party programs depend on non-Microsoft-signed libraries and may therefore fail to start under this policy. While there are Windows mechanisms that allow fine-grained exceptions for specific executables, these do not change the fact that enabling the policy system-wide creates a highly unstable environment and can selectively disable security-critical components.


---
## Conclusion

Enabling `MicrosoftSignedOnly` via `MitigationOptions` can cause many EDR products to become partially or completely non-functional. Their user-mode components cannot load because the operating system rejects all DLLs that are not Microsoft-signed, even when these libraries are correctly signed by the vendor. The result is a system that appears operational but is effectively unprotected and blind.

Although the mitigation also restricts certain attacker techniques, the loss of visibility and security monitoring for affected EDR products is significantly more severe.

----
