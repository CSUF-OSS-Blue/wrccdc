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

# Get running processes
consolidated_output+="\033[1;31mAll processes:\n\033[0m"
consolidated_output+="$(run_command 'ps aux')\n"
consolidated_output+="------------------------------------------\n"

# Get root processes
consolidated_output+="\033[1;31mRoot processes:\n\033[0m"
consolidated_output+="$(run_command 'ps aux | grep root')\n"
consolidated_output+="------------------------------------------\n"

# Write consolidated output to file
output_file="/tmp/proc-enum.txt"
echo -e "$consolidated_output" > "$output_file"
chmod 0777 "$output_file"
echo "Consolidated output written to $output_file"
