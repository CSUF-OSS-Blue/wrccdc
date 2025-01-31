#!/bin/ash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run a command and capture its output
run_command() {
    local cmd="$1"
    local output
    output=$(eval "$cmd" 2>/dev/null)
    echo "$output"
}

# Initialize consolidated output
consolidated_output=""

# Get list of active services running
if command_exists rc-status; then
    consolidated_output+="Active Services:\n"
    consolidated_output+="$(run_command 'rc-status')\n"
    consolidated_output+="------------------------------------------\n"
fi

# Check if netstat is installed
if command_exists netstat; then
    netstat_installed=true
else
    netstat_installed=false
fi

# Get tcp, udp, pid, addy + port for listening ports
if $netstat_installed; then
    consolidated_output+="Listening ports (netstat):\n"
    consolidated_output+="$(run_command 'netstat -tulnp')\n"
else
    consolidated_output+="Listening ports (ss):\n"
    consolidated_output+="$(run_command 'ss -tuln')\n"
fi
consolidated_output+="------------------------------------------\n"

# Get connections, addresses/ports, tcp, udp, pid, and unix domain sockets
if $netstat_installed; then
    consolidated_output+="Connections, addresses/ports, tcp, udp, pid, and unix domain sockets:\n"
    consolidated_output+="$(run_command 'netstat -antupx')\n"
    consolidated_output+="------------------------------------------\n"
fi

# Get distro and version
consolidated_output+="Versions and distro:\n"
consolidated_output+="$(run_command 'cat /etc/*-release')\n"
consolidated_output+="------------------------------------------\n"

# Get kernel version
consolidated_output+="Kernel version:\n"
consolidated_output+="$(run_command 'cat /proc/version')\n"
consolidated_output+="------------------------------------------\n"

# Get running processes
consolidated_output+="All processes:\n"
consolidated_output+="$(run_command 'ps aux')\n"
consolidated_output+="------------------------------------------\n"

# Get root processes
consolidated_output+="Root processes:\n"
consolidated_output+="$(run_command 'ps aux | grep root')\n"
consolidated_output+="------------------------------------------\n"

# Get installed apps/packages, versions, and if they are running
consolidated_output+="Installed packages:\n"
consolidated_output+="$(run_command 'apk info')\n"
consolidated_output+="------------------------------------------\n"

# Get individual cron jobs
consolidated_output+="Individual cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/cron.d/*')\n"
consolidated_output+="------------------------------------------\n"

# Get daily cron jobs
consolidated_output+="Daily cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/cron.daily/*')\n"
consolidated_output+="------------------------------------------\n"

# Get hourly cron jobs
consolidated_output+="Hourly cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/cron.hourly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get weekly cron jobs
consolidated_output+="Weekly cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/cron.weekly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get monthly cron jobs
consolidated_output+="Monthly cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/cron.monthly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get system wide cron jobs
consolidated_output+="System wide cron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/crontab')\n"
consolidated_output+="------------------------------------------\n"

# Get anacron jobs
consolidated_output+="Anacron jobs:\n"
consolidated_output+="$(run_command 'cat /etc/anacrontab')\n"
consolidated_output+="------------------------------------------\n"

# Get active interfaces (including inactive/down), IP address, MAC, netmask, broadcast, and more
consolidated_output+="Active interfaces:\n"
consolidated_output+="$(run_command 'ifconfig -a')\n"
consolidated_output+="------------------------------------------\n"

# Check if ip is installed
if command_exists ip; then
    ip_installed=true
else
    ip_installed=false
fi

# Get links/network interfaces
if $ip_installed; then
    consolidated_output+="Connected interfaces:\n"
    consolidated_output+="$(run_command 'ip link')\n"
    consolidated_output+="------------------------------------------\n"
fi

# Get network interface configuration
consolidated_output+="Network interface configuration:\n"
consolidated_output+="$(run_command 'cat /etc/network/interfaces')\n"
consolidated_output+="------------------------------------------\n"

# Get files + processes related to internet/network connections
consolidated_output+="All files and processes related to network connections:\n"
consolidated_output+="$(run_command 'lsof -i')\n"
consolidated_output+="------------------------------------------\n"

# Get files + processes but only port 80
consolidated_output+="Files and processes related to port 80:\n"
consolidated_output+="$(run_command 'lsof -i :80')\n"
consolidated_output+="------------------------------------------\n"

# Get mounted filesystems
consolidated_output+="Mounted filesystems:\n"
consolidated_output+="$(run_command 'mount')\n"
consolidated_output+="------------------------------------------\n"

# Get disk space usage for mounted filesystems
consolidated_output+="Disk space usage:\n"
consolidated_output+="$(run_command 'df -h')\n"
consolidated_output+="------------------------------------------\n"

# Detect unmounted file-systems
consolidated_output+="Unmounted filesystems:\n"
consolidated_output+="$(run_command 'cat /etc/fstab')\n"
consolidated_output+="------------------------------------------\n"

# Get world writable folders
consolidated_output+="World writable folders:\n"
consolidated_output+="$(run_command 'find / -xdev -type d -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Get world writable files
consolidated_output+="World writable files:\n"
consolidated_output+="$(run_command 'find / -xdev -type f -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Write consolidated output to file
output_file="/home/enum.txt"
echo -e "$consolidated_output" > "$output_file"
chmod 0777 "$output_file"

echo "Consolidated output written to $output_file"