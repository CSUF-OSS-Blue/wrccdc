#!/bin/bash

command_exists(){
    command -v "$1" >/dev/null 2>&1
}

run_command() {
    local cmd="$1"
    local output
    output=$(eval "$cmd" 2>/dev/null)
    echo "$output"
}


consolidated_output = ""

consolidated_output+="Installed packages:\n"
consolidated_output+="$(run_command 'apk info')\n"
consolidated_output+="------------------------------------------\n"

output_file = "/home/linux-software.txt"
echo -e "$consolidated_output" > "$output_file"
chmod 0777 "$output_file"

echo "Consolidated output written to $output_file"
