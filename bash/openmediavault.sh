#!/bin/bash

# Exit on error
set -e

# Update and upgrade system
apt update && apt upgrade -y

# Install OpenMediaVault prerequisites
apt install -y wget gnupg lsb-release

# Add OpenMediaVault repo and key
wget -O - https://packages.openmediavault.org/public/archive.key | apt-key add -
echo "deb https://packages.openmediavault.org/public $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/openmediavault.list

# Update repositories and install OpenMediaVault
apt update
apt install -y openmediavault

# Initialize config database
omv-confdbadm populate

# Enable SSH
omv-salt deploy run ssh
systemctl enable ssh
systemctl start ssh

# Install OMV-Extras for Docker and plugins
wget https://github.com/OpenMediaVault-Plugin-Developers/packages/raw/master/install/install-omv-extras.sh
bash install-omv-extras.sh

# Deploy Docker plugin
omv-salt deploy run omvextras
omv-salt deploy run docker

# Example: Create a shared folder (customize as needed)
# Replace '/srv/dev-disk-by-uuid-xxxx' with your actual drive mount
SHARE_PATH="/srv/dev-disk-by-uuid-your-uuid"
mkdir -p "$SHARE_PATH/data"

# Add a user
omv-rpc usermgmt create '{"name":"nasuser","password":"strongpassword","groups":["users"]}'

# Create shared folder and configure SMB share
omv-rpc sharedfolder create '{"name":"nasdata","comment":"NAS Share","path":"data","devicefile":"'"$SHARE_PATH"'"}'
omv-rpc smb share create '{"sharedfolderref":1,"name":"nasdata","comment":"NAS share via script"}'

# Enable SMB
omv-salt deploy run samba

echo "OpenMediaVault installation and sample configuration complete."
