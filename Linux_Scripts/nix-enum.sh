#! /usr/bin/env nix-shell
#! nix-shell -i bash -p bash

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
distro_version=$(cat /etc/*-release)
kernel_version=$(cat /proc/version)
versions_content="Versions and distro:\n$distro_version\n------------------------------------------\nKernel version:\n$kernel_version"
append_to_file "$versions_content"

# Get running processes
processes=$(ps aux)
root_processes=$(ps aux | grep root)
processes_content="All processes:\n$processes\n------------------------------------------\nRoot processes:\n$root_processes"
append_to_file "$processes_content"

# Get nix config and packages
nix_config=$(cat /etc/nixos/configuration.nix 2>/dev/null)
nix_live=$(nix-store --gc --print-live 2>/dev/null)
nix_pkgs_content="cat /etc/nixos/configuration.nix:\n$nix_config\n------------------------------------------\nnix-store --gc --print-live:\n$nix_live"
append_to_file "$nix_pkgs_content"

# Check if ifconfig is installed
if command -v ifconfig &> /dev/null; then
    ifconfig_interfaces=$(ifconfig -a)
    network_info="Active interfaces:\n$ifconfig_interfaces"
else
    network_info="ifconfig not installed"
fi

# Get connected interfaces
if command -v ip &> /dev/null; then
    connected_interfaces=$(ip link)
    network_info="$network_info\n------------------------------------------\nConnected interfaces:\n$connected_interfaces"
fi

# Get network interface configuration
if [ -f /etc/network/interfaces ]; then
    debian_interfaces=$(cat /etc/network/interfaces)
    network_info="$network_info\n------------------------------------------\nNetwork interface configuration (debian):\n$debian_interfaces"
elif [ -f /etc/netplan/*.yaml ]; then
    netplan_interfaces=$(cat /etc/netplan/*.yaml)
    network_info="$network_info\n------------------------------------------\nNetwork interface configuration (ubuntu 20.04+):\n$netplan_interfaces"
elif [ -f /etc/sysconfig/network-scripts/ifcfg-* ]; then
    redhat_interfaces=$(cat /etc/sysconfig/network-scripts/ifcfg-*)
    network_info="$network_info\n------------------------------------------\nNetwork interface configuration (redhat):\n$redhat_interfaces"
fi
append_to_file "$network_info"

# Get user login history
login_history=$(last)
logged_in_users=$(w)
login_history_content="Login history:\n$login_history\n------------------------------------------\nLogged in users:\n$logged_in_users"
append_to_file "$login_history_content"

# Get sudoers file
sudoers=$(cat /etc/sudoers)
append_to_file "$sudoers"

# Get files and directories in /root/
root_files=$(ls -ahlR /root/)
append_to_file "$root_files"

# Get bash and zsh history
bash_history=$(cat ~/.bash_history 2>/dev/null)
zsh_history=$(cat ~/.zsh_history 2>/dev/null)
history_content="Bash history:\n$bash_history\n------------------------------------------\nZsh history:\n$zsh_history"
append_to_file "$history_content"

# Get SSH keys
ssh_keys=$(cat ~/.ssh/* 2>/dev/null)
append_to_file "$ssh_keys"

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