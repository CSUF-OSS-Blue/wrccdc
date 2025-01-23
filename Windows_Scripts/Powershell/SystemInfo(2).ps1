#copy and paste into powershell can't just run this apparently
systeminfo | findstr "OS Version" | Out-File -FilePath ".systeminfo.txt"
netstat -an | Out-File -FilePath ".ports.txt"

Get-Process | Where-Object { $_.MainWindowTitle -eq "" } | Out-File -FilePath ".Winprocess.txt"
Get-Service | Where-Object { $_.Status -eq 'Running' } | Out-File -FilePath ".Runningprocess.txt"

# List of registry paths where installed applications are recorded
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$apps = @()

foreach ($regPath in $regPaths) {
    $apps += Get-ItemProperty $regPath | Where-Object {
        $_.DisplayName -and ($_.SystemComponent -ne 1) -and ($_.ReleaseType -ne 'Update')
    } | Select-Object DisplayName, DisplayVersion, Publisher
}

# Display the list of applications
$apps | Format-Table -AutoSize | Out-File -FilePath ".installedApps.txt"