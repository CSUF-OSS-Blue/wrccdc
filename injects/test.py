import re
from collections import Counter

# Define the file paths
log_file_path = "/var/log/auth.log"
output_file_path = "login_attempts_summary.txt"

# Initialize counters
total_attempts = 0
failed_attempts = 0
successful_attempts = 0
account_attempts = Counter()

# Regular expressions to match failed and successful login attempts
failed_login_pattern = re.compile(r"Failed password for (?P<user>\S+)")
successful_login_pattern = re.compile(r"Accepted password for (?P<user>\S+)")

# Read the log file and process each line
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        # Match failed login attempts
        failed_match = failed_login_pattern.search(line)
        if failed_match:
            total_attempts += 1
            failed_attempts += 1
            account_attempts[failed_match.group("user")] += 1
            continue  # Skip to the next line

        # Match successful login attempts
        successful_match = successful_login_pattern.search(line)
        if successful_match:
            total_attempts += 1
            successful_attempts += 1
            account_attempts[successful_match.group("user")] += 1

# Get the top 10 accounts responsible for logins
top_accounts = account_attempts.most_common(10)

# Write the results to the output file
with open(output_file_path, 'w') as output_file:
    output_file.write(f"Total login attempts: {total_attempts}\n")
    output_file.write(f"Total successful login attempts: {successful_attempts}\n")
    output_file.write(f"Total failed login attempts: {failed_attempts}\n")
    output_file.write("\nTop 10 accounts by login attempts:\n")
    for account, count in top_accounts:
        output_file.write(f"{account}: {count} attempts\n")

print(f"Login attempt summary saved to {output_file_path}")
