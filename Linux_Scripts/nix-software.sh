#! /usr/bin/env nix-shell
#! nix-shell -i bash -p bash

OUTPUT_DIR="/tmp"
OUTPUT_FILE="$OUTPUT_DIR/$(hostname)-installed-software.txt"

mkdir -p "$OUTPUT_DIR"

# Function to append output to file
append_to_file() {
    local content=$1
    echo -e "$content" >> "$OUTPUT_FILE"
}

# Get nix config and packages
nix_config=$(cat /etc/nixos/configuration.nix 2>/dev/null)
nix_live=$(nix-store --gc --print-live 2>/dev/null)
nix_pkgs_content="cat /etc/nixos/configuration.nix:\n$nix_config\n------------------------------------------\nnix-store --gc --print-live:\n$nix_live"
append_to_file "$nix_pkgs_content"
