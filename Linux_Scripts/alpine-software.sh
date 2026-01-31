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

# Get installed apps/packages, versions, and if they are running
consolidated_output+="Installed packages:\n"
consolidated_output+="$(run_command 'apk info')\n"
consolidated_output+="------------------------------------------\n"

# Write consolidated output to file
output_file="/tmp/installed-software.txt"
echo -e "$consolidated_output" > "$output_file"
chmod 0777 "$output_file"

echo "Consolidated output written to $output_file"
