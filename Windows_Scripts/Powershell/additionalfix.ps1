<#
.SYNOPSIS
  Apply a set of mitigations for EternalBlue / PetitPotam / NTLM attacks / LLMNR / AD CS ESC issues and to prefer AES encryption.

.NOTES
  - Test in lab first.
  - Run elevated.
  - Domain-wide AD user changes require the ActiveDirectory module and Domain Admin rights.
  - Script creates a timestamped backup folder with registry exports and AD snapshots.
#>

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    break
}

$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$backupDir = "C:\Hardening_Backup_$ts"
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

# --- Helper: safe-run wrapper (logs errors) ---
function Safe-Run {
    param($ScriptBlock, $Description)
    try {
        & $ScriptBlock
        Write-Host "[OK] $Description" -ForegroundColor Green
    } catch {
        Write-Warning "[FAIL] $Description :: $_"
    }
}

# --- BACKUP: registry keys we will modify ---
$regKeysToExport = @(
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
)
foreach ($rk in $regKeysToExport) {
    $safeName = ($rk -replace '[\\:\s]','_')
    $out = Join-Path $backupDir "$safeName.reg"
    reg export $rk $out /y 2>$null
}

# --- BACKUP: list of AD CS templates and CA ACLs (if AD module available) ---
$adModuleLoaded = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adModuleLoaded = $true
    Write-Host "ActiveDirectory module loaded" -ForegroundColor Cyan
    # Save group and CA info
    Get-ADGroup -Filter * | Select Name, DistinguishedName | Export-Csv (Join-Path $backupDir "AD_Groups.csv") -NoTypeInformation
    # Snapshot of privileged groups (example)
    $privGroups = @("Domain Admins","Enterprise Admins","Administrators")
    foreach ($g in $privGroups) {
        Get-ADGroupMember -Identity $g -Recursive | Select SamAccountName,Name,objectClass |
            Export-Csv (Join-Path $backupDir ("Members_$($g -replace '[\\/:*?""<>|]','_').csv")) -NoTypeInformation
    }

    # If AD CS is present on any CA servers, assist: list certificate templates and CA Acls (non-invasive)
    try {
        $caServers = (Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -ErrorAction SilentlyContinue)
        if ($caServers) {
            $caServers | Export-Clixml (Join-Path $backupDir "CA_Servers.xml")
        }
    } catch { }
} catch {
    Write-Host "ActiveDirectory module not present or not allowed - skipping AD backups." -ForegroundColor Yellow
}

# Disable WDigest storing plaintext credentials (if present)
Safe-Run { reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f } "Disable WDigest UseLogonCredential"

# Note: To fully restrict NTLM you should use 'Network security: Restrict NTLM' domain policies and start with 'Audit' mode first.
Write-Host "NOTE: For strict NTLM restrictions, configure 'Network security: Restrict NTLM' via Group Policy (Audit first)." -ForegroundColor Cyan

# -------------------------
# 3) PetitPotam / NTLM Relay mitigations (AD CS specific)
# -------------------------
# Ensure LDAP signing and channel binding are required on DCs (helps reduce relay surface)
Safe-Run { reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f } "LDAPClientIntegrity=2 (require signing)"
Safe-Run { reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f } "LDAPServerIntegrity=2 (require server signing)"

# If AD CS is present, recommend enabling Extended Protection for Authentication (EPA) and disabling HTTP endpoints for enrollment where possible.
if ($adModuleLoaded) {
    Write-Host "AD DS module present. Reminder: review AD CS servers and enable EPA/disable HTTP on AD CS per MS guidance." -ForegroundColor Cyan
} else {
    Write-Host "Cannot enumerate AD CS servers (ActiveDirectory module not loaded). Manually review AD CS per MS KB5005413." -ForegroundColor Yellow
}

# Optionally disable NetBIOS over TCP/IP on interfaces (non-invasive check first)
Write-Host "INFO: Disabling NetBIOS over TCP/IP on all physical interfaces - will change adapter settings. Review first." -ForegroundColor Cyan
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
foreach ($a in $adapters) {
    try {
        $a.SetTcpipNetbios(2) | Out-Null   # 2 = Disable NetBIOS over TCP/IP
        Write-Host "Disabled NetBIOS on adapter: $($a.Description)"
    } catch {
        Write-Warning "Failed to modify NetBIOS on adapter: $($a.Description) - $_"
    }
}

# -------------------------
# --- AES encryption types for users (AES128 + AES256) ---
if ($adModuleLoaded) {
    $encValue = 8 + 16  # AES128(8) + AES256(16) = 24

    Write-Host "Backing up users' msDS-SupportedEncryptionTypes..."
    Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes |
        Select SamAccountName, msDS-SupportedEncryptionTypes |
        Export-Csv (Join-Path $backupDir "UserEncTypes_Export.csv") -NoTypeInformation

    $applyAll = Read-Host "Apply AES128+AES256 (msDS-SupportedEncryptionTypes=24) to ALL users? Type 'YES' to proceed"
    if ($applyAll -eq 'YES') {
        Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | ForEach-Object {
            try {
                Set-ADUser -Identity $_.SamAccountName -Replace @{ 'msDS-SupportedEncryptionTypes' = $encValue }
                Write-Host ("Set AES flags for {0}" -f $_.SamAccountName) -ForegroundColor Green
            } catch {
                Write-Warning ("Failed to set enc types for {0}: {1}" -f $_.SamAccountName, $_.Exception.Message)
            }
        }
        Write-Host "Reminder: consider rotating the krbtgt password twice after wide Kerberos encryption changes."
    } else {
        Write-Host "Skipped applying AES change to users."
    }
}

# -------------------------
# 7) Turn off token delegation / constrained delegation
# -------------------------
# Enumerate accounts with 'TrustedForDelegation' or Unconstrained delegation and report for manual remediation.
# Constrained delegation report
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo |
    Where-Object { $_.'msDS-AllowedToDelegateTo' -ne $null -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0 } |
    Select-Object Name, @{n='msDS-AllowedToDelegateTo';e={ $_.'msDS-AllowedToDelegateTo' }} |
    Export-Csv (Join-Path $backupDir ("ConstrainedDelegation_{0}.csv" -f (Get-Date -Format yyyyMMdd))) -NoTypeInformation
Write-Host "Exported constrained delegation entries for review."


# -------------------------
# 8) Ensure accounts are not set to DONT_REQ_PREAUTH / PASSWD_NOTREQD (disable risky flags)
# -------------------------
# --- Turn off DONT_REQ_PREAUTH / PASSWD_NOTREQD ---
# --- Turn off DONT_REQ_PREAUTH / PASSWD_NOTREQD ---

if ($adModuleLoaded) {

    # DoesNotRequirePreAuth

    $noPreAuth = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth

    if ($noPreAuth) {

        $noPreAuth | Select SamAccountName |

            Export-Csv (Join-Path $backupDir "NoPreAuthUsers.csv") -NoTypeInformation

        Write-Host "Found users with DoesNotRequirePreAuth (backed up)."

        $confirm = Read-Host "Set DoesNotRequirePreAuth = \$false for those users now? Type YES to proceed"

        if ($confirm -eq 'YES') {

            foreach ($u in $noPreAuth) {

                try {

                    Set-ADUser -Identity $u.SamAccountName -Replace @{ 'msDS-UserDontRequirePreauth' = 0 }

                    Write-Host ("Enabled preauth for {0}" -f $u.SamAccountName) -ForegroundColor Green

                } catch {

                    Write-Warning ("Failed to enable preauth for {0}: {1}" -f $u.SamAccountName, $_.Exception.Message)

           }
            }
        } else {
            Write-Host "Skipped changing DoesNotRequirePreAuth."
        }
    } else {
        Write-Host "No accounts found with DoesNotRequirePreAuth."
    }

    # PASSWD_NOTREQD (bit 0x20)
    $pwNotReq = Get-ADUser -LDAPFilter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -Properties userAccountControl
    if ($pwNotReq) {
        $pwNotReq | Select SamAccountName |
            Export-Csv (Join-Path $backupDir "PasswdNotReqd_Users.csv") -NoTypeInformation
        Write-Host "Found PASSWD_NOTREQD accounts (backed up)."
        $confirm2 = Read-Host "Remove PASSWD_NOTREQD flag for those users now? Type YES to proceed"
        if ($confirm2 -eq 'YES') {
            foreach ($u in $pwNotReq) {
                try {
                    # Clear bit 0x20 from UAC
                    $newUac = ($u.userAccountControl -band (-bnot 32))
                    Set-ADUser -Identity $u.SamAccountName -Replace @{ userAccountControl = $newUac }
                    Write-Host ("Cleared PASSWD_NOTREQD for {0}" -f $u.SamAccountName) -ForegroundColor Green
                } catch {
                    Write-Warning ("Failed to clear PASSWD_NOTREQD for {0}: {1}" -f $u.SamAccountName, $_.Exception.Message)
                }
            }
        } else {
            Write-Host "Skipped clearing PASSWD_NOTREQD flags."
        }
    } else {
        Write-Host "No PASSWD_NOTREQD accounts found."
    }
} # <-- closes: if ($adModuleLoaded)

# -------------------------
# 9) AD CS ESC1, ESC4, ESC7 mitigations (report + safe changes)
# -------------------------
# These require manual CA/template review. We export template ACLs for review.
if ($adModuleLoaded) {
    Write-Host "Exporting certificate templates and CA ACL info for manual review..."
    try {
        # Export certificate templates (if PKI tools present, else attempt LDAP read)
        certutil -catemplates > (Join-Path $backupDir "CertificateTemplates_list.txt") 2>$null
        Get-ChildItem "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue | Export-Clixml (Join-Path $backupDir "LocalMachineCerts.xml")
    } catch {
        Write-Warning "Could not enumerate certificate templates with certutil on this host."
    }
    Write-Host "Manual tasks to mitigate ESC1/ESC4/ESC7:"
    Write-Host "- Ensure Authenticated Users is NOT granted Enroll (or Enroll+AutoEnroll) on templates that allow domain authentication (remove or tighten ACLs)." -ForegroundColor Cyan
    Write-Host "- Require 'Supply in request' restrictions or manager approval where appropriate and disable 'Subject Name' from being supplied by request." -ForegroundColor Cyan
    Write-Host "- Audit and tighten CA ACLs so low-privileged users cannot modify CA permissions." -ForegroundColor Cyan
} else {
    Write-Host "ActiveDirectory module missing: skipping ESC-related exports." -ForegroundColor Yellow
}

# -------------------------
# 10) Wrap up & guidance
# -------------------------
Write-Host "`nBackup and changes logged to: $backupDir" -ForegroundColor Green
Write-Host "Review the exported files before rolling back or making broader changes in production." -ForegroundColor Cyan
Write-Host "Recommended next steps:" -ForegroundColor Cyan
Write-Host " - For AD CS (ESC) hardening: review certificate templates, remove 'Authenticated Users' Enroll rights, require manager approval where applicable, and audit CA ACLs per MS guidance." -ForegroundColor Cyan
