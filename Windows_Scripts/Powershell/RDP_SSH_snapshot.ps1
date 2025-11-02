#Requires -RunAsAdministrator
$ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
$root = "C:\CCDC_Snapshot"
$dest = Join-Path $root "$env:COMPUTERNAME-RDP-SSH-$ts"
$rdp  = Join-Path $dest "RDP"
$ssh  = Join-Path $dest "SSH"
$sys  = Join-Path $dest "System"

New-Item -ItemType Directory -Path $rdp,$ssh,$sys -Force | Out-Null

# -------- RDP: registry, policies, cert info, firewall, groups, services --------
$kRdpTS   = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
$kRdpTcp  = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$kRdpPol  = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

& reg.exe export "$kRdpTS"  (Join-Path $rdp 'TerminalServer.reg') /y | Out-Null
& reg.exe export "$kRdpTcp" (Join-Path $rdp 'RDP-Tcp.reg') /y | Out-Null
& reg.exe export "$kRdpPol" (Join-Path $rdp 'TerminalServices_Policies.reg') /y 2>$null

$rdpVals = @{
  fDenyTSConnections = (Get-ItemProperty "$kRdpTS" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
  UserAuthentication = (Get-ItemProperty "$kRdpTcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
  SecurityLayer      = (Get-ItemProperty "$kRdpTcp" -Name SecurityLayer -ErrorAction SilentlyContinue).SecurityLayer
  MinEncryptionLevel = (Get-ItemProperty "$kRdpTcp" -Name MinEncryptionLevel -ErrorAction SilentlyContinue).MinEncryptionLevel
}
$rdpVals.GetEnumerator() | Sort-Object Name | Out-File (Join-Path $rdp 'rdp_current_values.txt')

& net.exe localgroup "Remote Desktop Users" > (Join-Path $rdp 'RemoteDesktopUsers.txt')

# Firewall rules (TXT instead of CSV)
$rdpFwTxt = Join-Path $rdp 'firewall_rdp_rules.txt'
(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' |
  Select-Object Name,DisplayName,Enabled,Direction,Action,Profile |
  Format-Table -AutoSize | Out-String) | Set-Content $rdpFwTxt

# Service config for RDP (TermService)
& sc.exe qc TermService > (Join-Path $rdp 'service_TermService.txt')

# RDP certificate store listing
& certutil.exe -store "Remote Desktop" > (Join-Path $rdp 'rdp_cert_store.txt')

# Also export entire firewall policy (binary .wfw)
$fwFile = Join-Path $rdp 'firewall.wfw'
& netsh.exe advfirewall export "$fwFile" | Out-Null

# -------- SSH: config, host keys, firewall, service, authorized_keys --------
$sshDir = 'C:\ProgramData\ssh'
if (Test-Path $sshDir) {
  Copy-Item (Join-Path $sshDir 'sshd_config') $ssh -ErrorAction SilentlyContinue
  Copy-Item (Join-Path $sshDir 'ssh_config')  $ssh -ErrorAction SilentlyContinue
  Get-ChildItem $sshDir -Filter 'ssh_host_*' -ErrorAction SilentlyContinue | Copy-Item -Destination $ssh -Force
  if (Test-Path (Join-Path $sshDir 'logs')) {
    Copy-Item (Join-Path $sshDir 'logs\*') (Join-Path $ssh 'logs') -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path (Join-Path $sshDir 'sshd_config')) {
    & icacls.exe (Join-Path $sshDir 'sshd_config') > (Join-Path $ssh 'sshd_config.acl.txt')
  }
}

Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  $ak = Join-Path $_.FullName '.ssh\authorized_keys'
  if (Test-Path $ak) {
    Copy-Item $ak (Join-Path $ssh ("authorized_keys_{0}.txt" -f $_.Name)) -Force
  }
}

# SSH firewall rules (TXT instead of CSV)
$sshFwTxt = Join-Path $ssh 'firewall_ssh_rules.txt'
(Get-NetFirewallRule | Where-Object { $_.DisplayName -match 'OpenSSH' -or $_.Name -match 'OpenSSH' } |
  Select-Object Name,DisplayName,Enabled,Direction,Action,Profile |
  Format-Table -AutoSize | Out-String) | Set-Content $sshFwTxt

# Service config + status (TXT instead of CSV)
& sc.exe qc sshd > (Join-Path $ssh 'service_sshd.txt') 2>$null
(Get-Service -Name sshd -ErrorAction SilentlyContinue |
  Select-Object Name,Status,StartType |
  Format-List | Out-String) | Set-Content (Join-Path $ssh 'service_sshd_status.txt')

# -------- System context --------
& secedit.exe /export /cfg (Join-Path $sys 'secpol.cfg') /areas SECURITYPOLICY | Out-Null
gpresult /h (Join-Path $sys 'gpresult.html') /f | Out-Null

# Manifest
@"
Backup host: $env:COMPUTERNAME
Timestamp:   $ts
Paths:       $dest
"@ | Out-File (Join-Path $dest 'MANIFEST.txt')

# Zip it up
$zip = "$dest.zip"
Compress-Archive -Path $dest -DestinationPath $zip -Force
Write-Host "Backup complete."
Write-Host "Folder: $dest"
Write-Host "Zip:    $zip"