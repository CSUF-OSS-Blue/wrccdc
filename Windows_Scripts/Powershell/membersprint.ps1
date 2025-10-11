Import-Module ActiveDirectory

$groups = @(
  "Domain Admins","Enterprise Admins","Administrators",
  "DnsAdmins","Group Policy Creator Owners","Schema Admins",
  "Key Admins","Enterprise Key Admins", "Domain Controllers", "Domain Users", "Domain Guests"
)

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$backupDir = "C:\AD_Backups\GroupMembershipBackup_$ts"
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

foreach ($g in $groups) {
    $safeName = ($g -replace '[\\/:*?"<>|]','_')

    # Collect members once so we can both print and export
    $members = Get-ADGroupMember -Identity $g -Recursive |
               Select-Object SamAccountName, Name, objectClass |
               Sort-Object SamAccountName

    # 1) Print a header + table to the console
    Write-Host "`n====================== $g ======================" -ForegroundColor Cyan
    if ($members) {
        $members | Format-Table SamAccountName, Name, objectClass -AutoSize | Out-String -Width 4096 | Write-Host
    } else {
        Write-Host "(no members)" -ForegroundColor Yellow
    }

    # 2) Save to CSV
    $csvPath = Join-Path $backupDir "$safeName-members.csv"
    $members | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    # (optional) Also save a pretty text table next to the CSV
    $txtPath = Join-Path $backupDir "$safeName-members.txt"
    ($members | Format-Table SamAccountName, Name, objectClass -AutoSize | Out-String -Width 4096) |
        Set-Content -Path $txtPath -Encoding UTF8

    Write-Host "Saved: $csvPath"
}
Write-Host "`nBackup complete: $backupDir" -ForegroundColor Green
