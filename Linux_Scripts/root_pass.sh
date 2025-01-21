#!/bin/bash

ROOT_USER="root"
PASSWORD_FILE="/home/$(hostname)-new_root_pass.txt"

# Function to generate a random password
generate_password() {
    local length=$1
    tr -dc 'A-Za-z0-9!@#$%^&*()_+{}|:<>?=' < /dev/urandom | head -c $length
}

# Generate a new password for the root user
ROOT_PASSWORD=$(generate_password 16)

# Change the password for the root user
echo "${ROOT_USER}:${ROOT_PASSWORD}" | chpasswd

# Print the new root password
echo "New root password: ${ROOT_PASSWORD}"

# Save the new password to a file
echo "New root password: ${ROOT_PASSWORD}" > "$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"

echo "Password has been changed and saved to $PASSWORD_FILE"