#!/bin/bash

OUTPUT_DIR="/home"
OUTPUT_FILE="$OUTPUT_DIR/$(hostname)-enumeration.txt"

mkdir -p "$OUTPUT_DIR"

# Function to append output to file
append_to_file() {
    local content=$1
    echo -e "$content" >> "$OUTPUT_FILE"
}

# Get list of active services running
services_run=$(systemctl list-units --type=service --state=running)
services_all=$(systemctl list-units --type=service)
service_content="Active Services:\n$services_run\n------------------------------------------\nAll Services:\n$services_all"
append_to_file "$service_content"

# Check if netstat is installed
if command -v netstat &> /dev/null; then
    ports_all=$(netstat -tulnp)
    connections=$(netstat -antupx)
    ports_content="Listening ports:\n$ports_all\n------------------------------------------\nConnections, addresses/ports, tcp, udp, pid, and unix domain sockets:\n$connections"
else
    ss_ports=$(ss -tuln)
    ports_content="Listening ports:\n$ss_ports"
fi
append_to_file "$ports_content"

# Get distro and version
if [ -f /etc/debian_version ]; then
    distro_version=$(cat /etc/*-release)
    append_to_file "Versions and distro:\n$distro_version"
elif [ -f /etc/redhat-release ]; then
    rhel_version=$(cat /etc/redhat-release)
    append_to_file "Versions and distro:\n$rhel_version"
fi

# Get kernel version
kernel_version=$(cat /proc/version)
append_to_file "Kernel version:\n$kernel_version"

# Get running processes
processes=$(ps aux)
root_processes=$(ps aux | grep root)
processes_content="All processes:\n$processes\n------------------------------------------\nRoot processes:\n$root_processes"
append_to_file "$processes_content"

# Get installed packages
if [ -f /etc/debian_version ]; then
    debian_packages=$(dpkg -l)
    append_to_file "Installed packages (Debian):\n$debian_packages"
elif [ -f /etc/redhat-release ]; then
    rhel_packages=$(rpm -qa)
    append_to_file "Installed packages (RedHat):\n$rhel_packages"
fi

# Get cron jobs
cron_jobs_individual=$(cat /etc/cron.d/* 2>/dev/null)
daily_cron_jobs=$(cat /etc/cron.daily/* 2>/dev/null)
hourly_cron_jobs=$(cat /etc/cron.hourly/* 2>/dev/null)
weekly_cron_jobs=$(cat /etc/cron.weekly/* 2>/dev/null)
monthly_cron_jobs=$(cat /etc/cron.monthly/* 2>/dev/null)
system_cron_jobs=$(cat /etc/crontab 2>/dev/null)
anacron_jobs=$(cat /etc/anacrontab 2>/dev/null)
cron_jobs_content="Individual cron jobs:\n$cron_jobs_individual\n------------------------------------------\nDaily cron jobs:\n$daily_cron_jobs\n------------------------------------------\nHourly cron jobs:\n$hourly_cron_jobs\n------------------------------------------\nWeekly cron jobs:\n$weekly_cron_jobs\n------------------------------------------\nMonthly cron jobs:\n$monthly_cron_jobs\n------------------------------------------\nSystem wide cron jobs:\n$system_cron_jobs\n------------------------------------------\nAnacron jobs:\n$anacron_jobs"
append_to_file "$cron_jobs_content"

# Get network interfaces
if command -v ifconfig &> /dev/null; then
    ifconfig_interfaces=$(ifconfig -a)
    append_to_file "Network interfaces (ifconfig):\n$ifconfig_interfaces"
fi

if command -v ip &> /dev/null; then
    interfaces=$(ip a)
    connected_interfaces=$(ip link)
    append_to_file "Network interfaces (ip):\n$interfaces\n------------------------------------------\nConnected interfaces:\n$connected_interfaces"
fi

# Get network interface configuration
if [ -f /etc/network/interfaces ]; then
    debian_interfaces=$(cat /etc/network/interfaces)
    append_to_file "Network interface configuration (Debian):\n$debian_interfaces"
elif [ -d /etc/netplan ]; then
    netplan_interfaces=$(cat /etc/netplan/*)
    append_to_file "Network interface configuration (Ubuntu 20.04+):\n$netplan_interfaces"
elif [ -f /etc/sysconfig/network-scripts/ifcfg-* ]; then
    redhat_interfaces=$(cat /etc/sysconfig/network-scripts/ifcfg-*)
    append_to_file "Network interface configuration (RedHat):\n$redhat_interfaces"
fi

# Get files and processes related to internet/network connections
network_files_processes=$(lsof -i)
port_80_files_processes=$(lsof -i :80)
network_files_content="Files + processes related to internet/network connections:\n$network_files_processes\n------------------------------------------\nFiles + processes but only port 80:\n$port_80_files_processes"
append_to_file "$network_files_content"

# Get user login history and currently logged in users
login_history=$(last)
logged_in_users=$(w)
login_history_content="User login history:\n$login_history\n------------------------------------------\nUsers currently logged in:\n$logged_in_users"
append_to_file "$login_history_content"

# Get sudoers file
sudoers=$(cat /etc/sudoers)
append_to_file "Sudoers file/permissions:\n$sudoers"

# Get files and directories in /root/
root_files=$(ls -ahlR /root/)
append_to_file "Files and directories/subdirectories in /root/ dir:\n$root_files"

# Get bash and zsh history
bash_history=$(cat ~/.bash_history 2>/dev/null)
zsh_history=$(cat ~/.zsh_history 2>/dev/null)
history_content="Bash history:\n$bash_history\n------------------------------------------\nZsh history:\n$zsh_history"
append_to_file "$history_content"

# Get SSH keys
ssh_keys=$(cat ~/.ssh/* 2>/dev/null)
append_to_file "SSH keys:\n$ssh_keys"

# Get mounted filesystems and disk space usage
mounted_filesystems=$(mount)
disk_space=$(df -h)
unmounted_filesystems=$(cat /etc/fstab)
disk_filesystem_content="Mounted filesystems:\n$mounted_filesystems\n------------------------------------------\nDisk space usage:\n$disk_space\n------------------------------------------\nUnmounted filesystems:\n$unmounted_filesystems"
append_to_file "$disk_filesystem_content"

# Get world writable folders and files
world_writable_folders=$(find / -xdev -type d -perm -0002 -ls 2>/dev/null)
world_writable_files=$(find / -xdev -type f -perm -0002 -ls 2>/dev/null)
world_writable_content="World writable folders:\n$world_writable_folders\n------------------------------------------\nWorld writable files:\n$world_writable_files"
append_to_file "$world_writable_content"