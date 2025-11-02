# Require Network Level Authentication (NLA) + TLS + High encryption
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'UserAuthentication' -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'SecurityLayer' -Value 2       # 2 = TLS (no legacy RDP security)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name 'MinEncryptionLevel' -Value 3  # 3 = High

# Reduce attack surface: block risky redirections (clipboard, drives, PnP, LPT)
New-Item 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null
Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableClip' 1 -Type DWord
Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm'  1 -Type DWord
Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fDisablePNPRedir' 1 -Type DWord
Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableLPT'  1 -Type DWord

# Limit who can RDP (put only necessary users in this group first)
# Example (adjust names): Add-LocalGroupMember 'Remote Desktop Users' -Member 'GC\youradmin'

# Account lockout to slow brute-force
cmd /c "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15"

# Firewall: allow RDP only from the invitational /24
New-NetFirewallRule -DisplayName 'RDP inbound (pod only)' -Direction Inbound -Protocol TCP `
  -LocalPort 3389 -RemoteAddress 192.168.220.0/24 -Action Allow
# Prefer this scoped rule over broad defaults
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Disable-NetFirewallRule
Enable-NetFirewallRule -DisplayName 'RDP inbound (pod only)'

# Sanity check
Test-NetConnection -ComputerName 127.0.0.1 -Port 3389