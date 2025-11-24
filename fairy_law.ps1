Write-Host "`n=== MicrosoftSignedOnly Check + Auto IFEO Handling + Setting Global Mitigation ===`n"

# ============================================
# Auto-Elevation: Relaunch as Administrator
# ============================================


$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Host "[!] Script is not running as Administrator. Elevating..."

    # Restart PowerShell as Administrator
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit   
    }
    catch {
        Write-Host "[-] Elevation cancelled or failed."
        exit 1
    }
}

Write-Host "[+] Running with Administrator privileges."


# ============================================================
# 1) LISTS
# ============================================================
# A) NEVER APPLY IFEO (SKIPPED)
$Exclusions = @(
    "specificNames",
    "placeholder"
)

# B) ALWAYS APPLY IFEO (FORCED)
$AutoProtect = @(
    "chrome",
    "otherExecutableNames"
)

Write-Host "ExclusionList: $($Exclusions -join ', ')" -ForegroundColor DarkGray
Write-Host "AutoProtectList: $($AutoProtect -join ', ')" -ForegroundColor DarkGray

# ============================================================
# 2) SIGNATURE CHECK
# ============================================================
function Is-MicrosoftSigned {
    param([string]$File)

    if (-not (Test-Path $File)) { return $true }

    $sig = Get-AuthenticodeSignature -FilePath $File
    if ($sig.Status -ne "Valid") { return $false }

    $issuer = $sig.SignerCertificate.Issuer
    return ($issuer -like "*Microsoft*" -or $issuer -like "*Windows*")
}

# ============================================================
# 3) REGISTRY LOOKUP TABLE
# ============================================================
$uninstall = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                                      HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
              -ErrorAction SilentlyContinue

$unsafe = @()

# ============================================================
# 4) MAIN OFFLINE CHECK + IFEO ACTION
# ============================================================
Get-Package | ForEach-Object {
    $name = $_.Name
    if (-not $name) { return }

    # A) Skip items in ExclusionList
    if ($Exclusions | Where-Object { $name -like "*$_*" }) {
        Write-Host "Skipping excluded program: $name" -ForegroundColor Yellow
        return
    }

    # B) Get install location
    $entry = $uninstall |
             Where-Object { $_.DisplayName -eq $name -and $_.InstallLocation -and (Test-Path $_.InstallLocation) } |
             Select-Object -First 1

    if (-not $entry) { return }

    $path = $entry.InstallLocation

    # C) Select main EXE
    $exe = Get-ChildItem -Path $path -Filter *.exe -File -ErrorAction SilentlyContinue |
           Select-Object -First 1

    if (-not $exe) { return }

    # D) Forced IFEO (AutoProtectList)
    if ($AutoProtect | Where-Object { $name -like "*$_*" }) {
        Write-Host "AutoProtect IFEO enabled for: $name ($($exe.Name))" -ForegroundColor Cyan
        Set-ProcessMitigation -Name $exe.Name -Disable MicrosoftSignedOnly 2>$null
        return
    }

    # E) Fast top-level DLL scan (offline)
    $dlls = Get-ChildItem -Path $path -Filter *.dll -File -ErrorAction SilentlyContinue
    foreach ($dll in $dlls) {

        if (-not (Is-MicrosoftSigned $dll.FullName)) {

            Write-Host "Adding IFEO exclusion for: $($exe.Name)" -ForegroundColor Cyan
            try {
                Set-ProcessMitigation -Name $exe.Name -Disable MicrosoftSignedOnly -ErrorAction Stop
            } catch {
                Write-Warning "Failed to set IFEO for $($exe.Name): $_"
            }

            $unsafe += [PSCustomObject]@{
                Program       = $name
                MainExe       = $exe.Name
                InstallPath   = $path
                FailingDLL    = $dll.Name
                MicrosoftOnly = "IFEO Disabled"
                Status        = "Would fail without IFEO"
            }

            break
        }
    }
}

# ============================================================
# 5) SHOW RESULTS
# ============================================================
if ($unsafe.Count -eq 0) {
    Write-Host "`nAll scanned programs appear compatible with MicrosoftSignedOnly." -ForegroundColor Green
} else {
    Write-Host "`nPrograms that WOULD FAIL but have been auto-excluded (IFEO):`n" -ForegroundColor Yellow
    $unsafe | Sort-Object Program | Format-Table -AutoSize
}

# ============================================================
# 6) ENABLE SYSTEM-WIDE MITIGATION
# ============================================================
Write-Host "`nEnabling system-wide MicrosoftSignedOnly...`n"

try {
    Set-ProcessMitigation -System -Enable MicrosoftSignedOnly
    Write-Host "System-wide MicrosoftSignedOnly ENABLED" -ForegroundColor Green
} catch {
    Write-Host "SYSTEM mitigation FAILED: $_" -ForegroundColor Red
}

# ============================================================
# 7) REBOOT THE SYSTEM
# ============================================================

for ($i = 10; $i -ge 1; $i--) {
    Write-Host "Continuing in $i..."
    Start-Sleep -Seconds 1
}
try {
    Restart-Computer -Force -Confirm:$false -ErrorAction Stop
}
catch {
    Write-Host "[-] Failed to reboot: $($_.Exception.Message)" -ForegroundColor Red
}
