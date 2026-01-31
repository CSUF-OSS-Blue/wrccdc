#/bin/bash

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

# Get world writable folders
consolidated_output+="\033[1;31mWorld writable folders:\n\033[0m"
consolidated_output+="$(run_command 'find / -xdev -type d -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Get world writable files
consolidated_output+="\033[1;31mWorld writable files:\n\033[0m"
consolidated_output+="$(run_command 'find / -xdev -type f -perm -0002 -ls 2>/dev/null')\n"
consolidated_output+="------------------------------------------\n"

# Write consolidated output to file
output_file="/tmp/writable-enum.txt"
echo -e "$consolidated_output" > "$output_file"
chmod 0777 "$output_file" 
echo "Consolidated output written to $output_file"
