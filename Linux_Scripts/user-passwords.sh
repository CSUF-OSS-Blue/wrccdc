#!/bin/bash

OUTPUT_DIR="/home"
OUTPUT_FILE="$OUTPUT_DIR/$(hostname)-new_passwords.txt"

mkdir -p "$OUTPUT_DIR"

# generate a random password
generate_password() {
    local length=$1
    tr -dc 'A-Za-z0-9!@#$%^&*()_+{}|:<>?=' < /dev/urandom | head -c $length
}

# list of users
users=$(awk -F: '$3 >= 1000 && $3 < 6000 {print $1}' /etc/passwd)

# Iassociative array to store passwords
declare -A user_passwords

# create new password for each user
for user in $users; do
    user_passwords[$user]=$(generate_password 16)
done

# change passwords
for user in "${!user_passwords[@]}"; do
    echo "${user}:${user_passwords[$user]}" | chpasswd
done

# prep file content
password_file_content=""
for user in "${!user_passwords[@]}"; do
    password_file_content+="User: $user, Password: ${user_passwords[$user]}\n"
done

# write to file
echo -e "$password_file_content" > "$OUTPUT_FILE"
chmod 0777 "$OUTPUT_FILE"

echo "Passwords have been changed and saved to $OUTPUT_FILE"