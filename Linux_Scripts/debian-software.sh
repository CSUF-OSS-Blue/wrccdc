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

# Get installed apps/packages (Debian/dpkg specific)
consolidated_output+="Installed packages (dpkg):\n"
consolidated_output+="$(run_command 'dpkg -l')\n"
consolidated_output+="------------------------------------------\n"

output_file="/tmp/installed-software.txt"

echo -e "$consolidated_output" > "$output_file"

# Check if file creation was successful
if [ $? -eq 0 ]; then
    chmod 0644 "$output_file" # 644 is safer than 777 for text files
    echo "Consolidated output written to $output_file"
else
    echo "Failed to write to $output_file. Try running with sudo or changing the output path to /tmp/enum.txt"
fi
