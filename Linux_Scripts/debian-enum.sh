#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run a command and capture its output
run_command() {
    local cmd="$1"
    local output
    output=$(eval "$cmd" 2>/dev/null)
    # Check if output is empty
    if [ -z "$output" ]; then
        echo "No output or command not found."
    else
        echo "$output"
    fi
}

# Initialize consolidated output
consolidated_output=""

# Get list of active services running (Systemd vs SysVinit)
consolidated_output+="\e[1;31mActive Services:\e[0m\n"
if command_exists systemctl; then
    consolidated_output+="$(run_command 'systemctl list-units --type=service --state=running')\n"
elif command_exists service; then
    consolidated_output+="$(run_command 'service --status-all | grep "+"')\n"
else
    consolidated_output+="\e[1;31mCould not detect service manager (systemd or service).\e[0m\n"
fi
consolidated_output+="------------------------------------------\n"

# Check if netstat is installed
if command_exists netstat; then
    netstat_installed=true
else
    netstat_installed=false
fi

# Get tcp, udp, pid, addy + port for listening ports
if $netstat_installed; then
    consolidated_output+="\e[1;31mListening ports (netstat):\e[0m\n"
    consolidated_output+="$(run_command 'netstat -tulnp')\n"
else
    consolidated_output+="\e[1;31mListening ports (ss):\e[0m\n"
    consolidated_output+="$(run_command 'ss -tuln')\n"
fi
consolidated_output+="------------------------------------------\n"

# Get connections, addresses/ports, tcp, udp, pid, and unix domain sockets
if $netstat_installed; then
    consolidated_output+="\e[1;31mConnections, addresses/ports, tcp, udp, pid, and unix domain sockets:\e[0m\n"
    consolidated_output+="$(run_command 'netstat -antupx')\n"
    consolidated_output+="------------------------------------------\n"
fi

# Get distro and version
consolidated_output+="\e[1;31mVersions and distro:\e[0m\n"
consolidated_output+="$(run_command 'cat /etc/*-release')\n"
consolidated_output+="------------------------------------------\n"

# Get kernel version
consolidated_output+="\e[1;31mKernel version:\e[0m\n"
consolidated_output+="$(run_command 'uname -a')\n"
consolidated_output+="$(run_command 'cat /proc/version')\n"
consolidated_output+="------------------------------------------\n"

# Get running processes
consolidated_output+="\e[1;31mAll processes:\e[0m\n"
consolidated_output+="$(run_command 'ps aux')\n"
consolidated_output+="------------------------------------------\n"

# Get root processes
consolidated_output+="\e[1;31mRoot processes:\e[0m\n"
consolidated_output+="$(run_command 'ps aux | grep ^root')\n"
consolidated_output+="------------------------------------------\n"

# Get installed apps/packages (Debian/dpkg specific)
# consolidated_output+="Installed packages (dpkg):\n"
# consolidated_output+="$(run_command 'dpkg -l')\n"
# consolidated_output+="------------------------------------------\n"

# Get individual cron jobs
consolidated_output+="\e[1;31mIndividual cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'ls -la /etc/cron.d/ && cat /etc/cron.d/*')\n"
consolidated_output+="------------------------------------------\n"

# Get daily cron jobs
consolidated_output+="\e[1;31mDaily cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'ls -la /etc/cron.daily/ && cat /etc/cron.daily/*')\n"
consolidated_output+="------------------------------------------\n"

# Get hourly cron jobs
consolidated_output+="\e[1;31mHourly cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'ls -la /etc/cron.hourly/ && cat /etc/cron.hourly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get weekly cron jobs
consolidated_output+="\e[1;31mWeekly cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'ls -la /etc/cron.weekly/ && cat /etc/cron.weekly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get monthly cron jobs
consolidated_output+="\e[1;31mMonthly cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'ls -la /etc/cron.monthly/ && cat /etc/cron.monthly/*')\n"
consolidated_output+="------------------------------------------\n"

# Get system wide cron jobs
consolidated_output+="\e[1;31mSystem wide cron jobs:\e[0m\n"
consolidated_output+="$(run_command 'cat /etc/crontab')\n"
consolidated_output+="------------------------------------------\n"

# Get anacron jobs
consolidated_output+="\e[1;31mAnacron jobs:\e[0m\n"
consolidated_output+="$(run_command 'cat /etc/anacrontab')\n"
consolidated_output+="------------------------------------------\n"

# Check if ip command exists (preferred over ifconfig in Debian)
if command_exists ip; then
    ip_installed=true
else
    ip_installed=false
fi

# Get active interfaces
consolidated_output+="\e[1;31mActive interfaces:\e[0m\n"
if $ip_installed; then
    consolidated_output+="$(run_command 'ip addr show')\n"
elif command_exists ifconfig; then
    consolidated_output+="$(run_command 'ifconfig -a')\n"
fi
consolidated_output+="------------------------------------------\n"

# Get links/network interfaces
if $ip_installed; then
    consolidated_output+="\e[1;31mConnected interfaces (ip link):\e[0m\n"
    consolidated_output+="$(run_command 'ip link')\n"
    consolidated_output+="------------------------------------------\n"
fi

# Get network interface configuration
consolidated_output+="\e[1;31mNetwork interface configuration:\e[0m\n"
# Check standard interfaces file
if [ -f /etc/network/interfaces ]; then
    consolidated_output+="\e[1;31m--- /etc/network/interfaces ---\e[0m\n"
    consolidated_output+="$(run_command 'cat /etc/network/interfaces')\n"
fi
# Check for Netplan (common in Ubuntu/Modern Debian)
if [ -d /etc/netplan ]; then
    consolidated_output+="\e[1;31m--- /etc/netplan/*.yaml ---\e[0m\n"
    consolidated_output+="$(run_command 'cat /etc/netplan/*.yaml')\n"
fi
consolidated_output+="------------------------------------------\n"

# Get files + processes related to internet/network connections
consolidated_output+="\e[1;31mAll files and processes related to network connections:\e[0m\n"
consolidated_output+="$(run_command 'lsof -i')\n"
consolidated_output+="------------------------------------------\n"

# Get files + processes but only port 80
consolidated_output+="\e[1;31mFiles and processes related to port 80:\e[0m\n"
consolidated_output+="$(run_command 'lsof -i :80')\n"
consolidated_output+="------------------------------------------\n"

# Get mounted filesystems
consolidated_output+="\e[1;31mMounted filesystems:\e[0m\n"
consolidated_output+="$(run_command 'mount | grep -v "sysfs\|proc\|cgroup"')\n" # Filtered for readability
consolidated_output+="------------------------------------------\n"

# Get disk space usage for mounted filesystems
consolidated_output+="\e[1;31mDisk space usage:\e[0m\n"
consolidated_output+="$(run_command 'df -h')\n"
consolidated_output+="------------------------------------------\n"

# Detect unmounted file-systems
consolidated_output+="\e[1;31mUnmounted filesystems (fstab):\e[0m\n"
consolidated_output+="$(run_command 'cat /etc/fstab')\n"
consolidated_output+="------------------------------------------\n"

# Get world writable folders
consolidated_output+="\e[1;31mWorld writable folders:\e[0m\n"
consolidated_output+="$(run_command 'find / -xdev -type d -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Get world writable files
consolidated_output+="\e[1;31mWorld writable files:\e[0m\n"
consolidated_output+="$(run_command 'find / -xdev -type f -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Write consolidated output to file
# Note: Writing to /home root usually requires sudo/root permissions. 
# If running as a standard user, change this to /tmp/enum.txt or /home/$USER/enum.txt
output_file="/tmp/enum.txt"

echo -e "$consolidated_output" > "$output_file"

# Check if file creation was successful
if [ $? -eq 0 ]; then
    chmod 0644 "$output_file" # 644 is safer than 777 for text files
    echo "Consolidated output written to $output_file"
else
    echo "Failed to write to $output_file. Try running with sudo or changing the output path to /tmp/enum.txt"
fi
