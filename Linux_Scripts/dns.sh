#!/bin/bash

# --- Configuration Variables ---
# On Debian/Ubuntu, main options are in named.conf.options
# On RHEL/CentOS, this might be directly in /etc/named.conf
BIND_OPTIONS_FILE="/etc/bind/named.conf.options"
BIND_LOG_DIR="/var/log/named"
SERVICE_NAME="bind9" # On RHEL/CentOS, this is typically "named"

# Checks
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

if [ ! -f "$BIND_OPTIONS_FILE" ]; then
    echo "BIND configuration file not found at $BIND_OPTIONS_FILE"
    echo "Please verify the path for your system."
    exit 1
fi

# Main Script
echo "--- Starting BIND9 Hardening ---"

# Backup the config file
cp "$BIND_OPTIONS_FILE" "${BIND_OPTIONS_FILE}.bak_$(date +%F-%T)"
echo "[*] Configuration file backed up to ${BIND_OPTIONS_FILE}.bak_..."

# Create log directory and set permissions
mkdir -p "$BIND_LOG_DIR"
chown -R bind:bind "$BIND_LOG_DIR"
echo "[*] Ensured log directory exists at $BIND_LOG_DIR"

# Apply baseline security settings
cat << EOF >> "$BIND_OPTIONS_FILE"

// --- CCDC Hardening Settings Added by Script ---

// Disable recursion to prevent use in amplification attacks
recursion no;

// Deny zone transfers by default to prevent network enumeration
allow-transfer { none; };

// Hide the BIND version number from queries
version "Not Disclosed";

// Basic logging configuration
logging {
    channel security_file {
        file "$BIND_LOG_DIR/security.log" versions 3 size 30m;
        severity dynamic;
        print-time yes;
    };
    category security {
        security_file;
    };
};

EOF

echo "[*] Applied security settings to $BIND_OPTIONS_FILE"

# Check the configuration for syntax errors
echo "[*] Checking BIND configuration for errors..."
named-checkconf

if [ $? -eq 0 ]; then
    echo "[SUCCESS] Configuration check passed."
    echo "[*] Restarting the BIND service ($SERVICE_NAME)..."
    systemctl restart "$SERVICE_NAME"
    systemctl status "$SERVICE_NAME" --no-pager
    echo "--- BIND Hardening Complete ---"
else
    echo "[ERROR] Configuration check failed. Please review $BIND_OPTIONS_FILE for errors."
    echo "--- Reverting to backup. ---"
    cp "${BIND_OPTIONS_FILE}.bak" "$BIND_OPTIONS_FILE"
    exit 1
fi