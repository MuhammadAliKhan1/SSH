#!/bin/bash

# ==============================================================================
# Script: setup_server.sh
# Description: Automates the initial security setup for a new Ubuntu server.
#              - Creates a new sudo user or configures an existing one.
#              - Configures the UFW firewall.
#              - Sets up SSH key-based authentication.
#              - Disables root login and password authentication.
# Author: Gemini
# ==============================================================================

# --- Configuration & Styling ---
COLOR_BLUE='\033[0;34m'
COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_NC='\033[0m' # No Color

# --- Helper Functions ---
info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"
}

success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} $1"
}

warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_NC} $1"
}

error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1"
    exit 1
}

# --- Cleanup Function ---
clean_ssh_config() {
    info "--- SSH Configuration Cleanup ---"
    warning "This will reset the SSH server configuration to allow password-based logins for all users, including root."
    warning "It will also DELETE the authorized_keys file for the user running the command to remove all existing SSH key access."
    read -p "Are you sure you want to proceed? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Cleanup cancelled."
        exit 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        error "This cleanup operation must be run with sudo. e.g., 'sudo ./setup_server.sh clean'"
    fi

    if [ -z "$SUDO_USER" ]; then
        error "Could not determine the user who ran sudo. Please run as a non-root user: 'sudo ./setup_server.sh clean'"
    fi

    info "Removing existing SSH keys for user '$SUDO_USER'..."
    # Get the home directory of the user who invoked sudo, which is more reliable than ~
    SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -f "${SUDO_USER_HOME}/.ssh/authorized_keys" ]; then
        rm -f "${SUDO_USER_HOME}/.ssh/authorized_keys"
        success "Successfully removed ${SUDO_USER_HOME}/.ssh/authorized_keys"
    else
        info "No authorized_keys file found for user '$SUDO_USER' to remove."
    fi

    info "Re-enabling password and root login in sshd_config..."
    # Use sed to uncomment and set the values to 'yes'
    sed -i -E 's/^[# ]*(PermitRootLogin|PasswordAuthentication).*/\1 yes/' /etc/ssh/sshd_config

    info "Restarting SSH service to apply changes..."
    systemctl restart ssh

    success "SSH configuration has been reset."
    info "The server will now accept password-based logins and has no configured SSH keys for '$SUDO_USER'."
    exit 0
}

# --- Fix Function ---
fix_ssh_config() {
    info "--- SSH Configuration Fix ---"
    info "This will connect to your server to fix the 'authorizedkeysfile' setting."
    
    read -p "Enter the server's IP address: " REMOTE_HOST
    if [ -z "$REMOTE_HOST" ]; then
        error "Server IP address cannot be empty."
    fi

    read -p "Enter a username with sudo privileges for the connection: " CONNECT_USER
    if [ -z "$CONNECT_USER" ]; then
        error "The connecting user cannot be empty."
    fi

    FIX_COMMANDS="
        echo '--- Applying SSH configuration fix ---';
        # This command finds the line, comments it out if it exists, and adds the correct one.
        sudo sed -i -E 's/^[# ]*AuthorizedKeysFile.*/# &/' /etc/ssh/sshd_config;
        echo 'AuthorizedKeysFile .ssh/authorized_keys' | sudo tee -a /etc/ssh/sshd_config;
        echo 'Restarting SSH service...';
        sudo systemctl restart ssh;
        echo '--- Fix applied successfully ---';
    "
    
    info "Connecting to apply fix..."
    ssh -t -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${CONNECT_USER}@${REMOTE_HOST}" "$FIX_COMMANDS"

    if [ $? -ne 0 ]; then
        error "Failed to connect and apply the fix."
    fi

    info "The server configuration has been fixed. Please re-run the main setup script now."
    exit 0
}


# --- Diagnostic Function ---
diagnose_ssh_config() {
    info "--- SSH Configuration Diagnostic ---"
    info "This will connect to your server to read its active SSH configuration."
    
    read -p "Enter the server's IP address: " REMOTE_HOST
    if [ -z "$REMOTE_HOST" ]; then
        error "Server IP address cannot be empty."
    fi

    read -p "Enter a username with sudo privileges for the connection: " CONNECT_USER
    if [ -z "$CONNECT_USER" ]; then
        error "The connecting user cannot be empty."
    fi

    DIAGNOSTIC_COMMANDS="
        echo '--- Active sshd_config settings ---';
        sudo grep -E '^[a-zA-Z]' /etc/ssh/sshd_config;
        echo;
        echo '--- Effective runtime SSH settings (sshd -T) ---';
        sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|pubkeyauthentication|authenticationmethods|authorizedkeysfile';
    "
    
    info "Connecting to run diagnostics..."
    ssh -t -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${CONNECT_USER}@${REMOTE_HOST}" "$DIAGNOSTIC_COMMANDS"

    if [ $? -ne 0 ]; then
        error "Failed to connect and run diagnostics."
    fi

    info "Please copy the output above and provide it for analysis."
    exit 0
}


# --- Main Script ---

# Check for 'clean', 'diagnose', or 'fix' argument
if [ "$1" == "clean" ]; then
    clean_ssh_config
fi
if [ "$1" == "diagnose" ]; then
    diagnose_ssh_config
fi
if [ "$1" == "fix" ]; then
    fix_ssh_config
fi

clear
echo "======================================================"
echo "      Initial Ubuntu Server Setup Script"
echo "======================================================"
echo
info "This script will perform a secure initial setup of a new Ubuntu server."
warning "You will need the server's IP address and the current 'root' password."
echo
read -p "Press [Enter] to begin..."

# --- Step 1: Gather Initial Information ---
info "--- Step 1: Gathering Server Information ---"
read -p "Enter the server's IP address: " REMOTE_HOST
if [ -z "$REMOTE_HOST" ]; then
    error "Server IP address cannot be empty."
fi

read -p "Enter the username for the initial connection (must have sudo privileges, e.g., root, ubuntu, ali): " CONNECT_USER
if [ -z "$CONNECT_USER" ]; then
    error "The connecting user cannot be empty."
fi
echo

read -p "Do you want to create a new user or configure an existing one? (new/existing): " USER_CHOICE
if [[ "$USER_CHOICE" != "new" && "$USER_CHOICE" != "existing" ]]; then
    error "Invalid choice. Please enter 'new' or 'existing'."
fi
echo

# --- Step 2: User Setup and Firewall Configuration ---
if [[ "$USER_CHOICE" == "new" ]]; then
    info "--- Step 2: Creating New User and Configuring Firewall ---"
    read -p "Enter the new username to create on the server: " TARGET_USER
    if [ -z "$TARGET_USER" ]; then
        error "New username cannot be empty."
    fi

    info "You will now be prompted to create a password for the new user '$TARGET_USER'."
    read -s -p "Enter a secure password for $TARGET_USER: " NEW_USER_PASSWORD
    echo
    read -s -p "Confirm password: " NEW_USER_PASSWORD_CONFIRM
    echo
    if [ "$NEW_USER_PASSWORD" != "$NEW_USER_PASSWORD_CONFIRM" ]; then
        error "Passwords do not match."
    fi
    ENCRYPTED_PASSWORD=$(openssl passwd -1 "$NEW_USER_PASSWORD")
    
    # Construct the command string to be executed remotely.
    # This avoids TTY issues with here-documents.
    SETUP_COMMANDS="
        sudo useradd -m -p '$ENCRYPTED_PASSWORD' -s /bin/bash '$TARGET_USER';
        sudo usermod -aG sudo '$TARGET_USER';
        echo 'User ''$TARGET_USER'' created and added to sudo group.';
        echo 'Configuring UFW firewall...';
        sudo ufw allow OpenSSH;
        sudo ufw allow http;
        sudo ufw allow https;
        yes | sudo ufw enable;
        sudo ufw status;
        echo 'Firewall configured and enabled.';
    "
    info "Connecting as '${CONNECT_USER}@${REMOTE_HOST}' to create user and configure firewall."
    ssh -t -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${CONNECT_USER}@${REMOTE_HOST}" "$SETUP_COMMANDS"
else
    info "--- Step 2: Configuring Firewall for Existing User ---"
    read -p "Enter the existing username to configure: " TARGET_USER
    if [ -z "$TARGET_USER" ]; then
        error "Existing username cannot be empty."
    fi

    # Construct the command string to be executed remotely.
    FIREWALL_COMMANDS="
        echo 'Configuring UFW firewall...';
        sudo ufw allow OpenSSH;
        sudo ufw allow http;
        sudo ufw allow https;
        yes | sudo ufw enable;
        sudo ufw status;
        echo 'Firewall configured and enabled.';
    "
    info "Connecting as '${CONNECT_USER}@${REMOTE_HOST}' to configure firewall."
    ssh -t -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${CONNECT_USER}@${REMOTE_HOST}" "$FIREWALL_COMMANDS"
fi

if [ $? -ne 0 ]; then
    error "Failed to perform server setup. Please check the root password and connection."
fi
success "Server configuration complete."
echo

# --- Step 3: Create and Copy SSH Key ---
info "--- Step 3: Setting Up SSH Key Authentication for '$TARGET_USER' ---"
PUBLIC_KEY_PATH="$HOME/.ssh/id_rsa.pub"
# Determine the corresponding private key path for use in the hardening step
PRIVATE_KEY_PATH="${PUBLIC_KEY_PATH%.pub}"

if [ ! -f "$PUBLIC_KEY_PATH" ]; then
    warning "No existing SSH key found. Generating a new one."
    ssh-keygen -t rsa -b 4096
    if [ $? -ne 0 ]; then
        error "SSH key generation failed."
    fi
else
    info "Existing SSH key found at '$PUBLIC_KEY_PATH'."
fi

info "Copying public key to '${TARGET_USER}@${REMOTE_HOST}'."
info "You will be prompted for the password for '$TARGET_USER'."
# We must also disable PubkeyAuthentication for ssh-copy-id to prevent the ssh-agent from interfering.
ssh-copy-id -i "$PUBLIC_KEY_PATH" -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${TARGET_USER}@${REMOTE_HOST}"
if [ $? -ne 0 ]; then
    error "Failed to copy the SSH key. Please check the password for '$TARGET_USER' and try again."
fi
success "SSH key copied successfully."

info "Enforcing correct file permissions on the server to prevent key rejection..."
PERMISSIONS_COMMAND="
    echo 'Setting strict permissions for home directory, .ssh, and authorized_keys...';
    chmod go-w ~;
    chmod 700 ~/.ssh;
    chmod 600 ~/.ssh/authorized_keys;
    echo 'Permissions successfully enforced.';
"
# We connect using the TARGET_USER's password one last time to enforce permissions.
ssh -t -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password "${TARGET_USER}@${REMOTE_HOST}" "$PERMISSIONS_COMMAND"
if [ $? -ne 0 ]; then
    error "Failed to enforce permissions on the server. This may be a password or sudo issue."
fi
success "Server-side permissions have been secured."
echo

# --- Step 4: Test Your Connection ---
info "--- Step 4: Test Your Connection ---"
warning "Please test your new key-based connection by running this command in a NEW terminal:"
echo -e "  ${COLOR_GREEN}ssh -i ${PRIVATE_KEY_PATH} -o IdentitiesOnly=yes ${TARGET_USER}@${REMOTE_HOST}${COLOR_NC}"
info "If it works, you can proceed to the final step to harden SSH security."
read -p "Press [Enter] after you have successfully tested the connection..."
echo

# --- Step 5: Harden SSH Security ---
info "--- Step 5: Harden SSH Security (Disable Root Login & Password Auth) ---"
warning "This final step will disable root login and password-based authentication."
warning "DO NOT PROCEED unless you have successfully logged in with your SSH key."
read -p "Are you sure you want to proceed? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Skipping SSH hardening. Your server is still accessible via password."
    exit 0
fi

info "Connecting as '$TARGET_USER' to harden SSH..."
info "You will be prompted for the sudo password for '$TARGET_USER'."

HARDEN_COMMANDS="
    echo 'Backing up sshd_config to /etc/ssh/sshd_config.bak';
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak;
    echo 'Disabling root login...';
    sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config;
    echo 'Disabling password authentication...';
    sudo sed -i 's/^[# ]*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config;
    echo 'Restarting SSH service to apply changes...';
    sudo systemctl restart ssh;
    # CRITICAL: Verify that the hardening was successful before disconnecting.
    EFFECTIVE_AUTH=$(sudo sshd -T | grep -i '^passwordauthentication' | awk '{print $2}');
    if [ "$EFFECTIVE_AUTH" != "no" ]; then
        echo -e '\n\nCRITICAL ERROR: Hardening check failed. PasswordAuthentication is NOT disabled.';
        echo 'Your server is still accepting passwords. Please investigate /etc/ssh/sshd_config manually.';
        exit 1;
    else
        echo 'Hardening successfully verified.';
    fi;
"
# This connection MUST use the specific key to avoid agent issues, just like the manual test.
ssh -t -i "$PRIVATE_KEY_PATH" -o IdentitiesOnly=yes "${TARGET_USER}@${REMOTE_HOST}" "$HARDEN_COMMANDS"

if [ $? -eq 0 ]; then
    success "SSH security hardened successfully."
    warning "Your server now ONLY accepts SSH key-based connections for the user '$TARGET_USER'."
else
    error "Failed to harden SSH security."
fi

echo
success "All done! Your new Ubuntu server is ready."

echo
echo -e "${COLOR_YELLOW}--- What To Do Next? ---${COLOR_NC}"
echo
info "Your server is now secure. Here are some common next steps:"
echo -e "1. ${COLOR_GREEN}Update your server's packages:${COLOR_NC}"
echo "   ssh -i ${PRIVATE_KEY_PATH} -o IdentitiesOnly=yes ${TARGET_USER}@${REMOTE_HOST} \"sudo apt update && sudo apt upgrade -y\""
echo
echo -e "2. ${COLOR_GREEN}Install a web server (like Nginx):${COLOR_NC}"
echo "   ssh -i ${PRIVATE_KEY_PATH} -o IdentitiesOnly=yes ${TARGET_USER}@${REMOTE_HOST} \"sudo apt install nginx -y\""
echo
echo -e "3. ${COLOR_GREEN}Install Docker:${COLOR_NC}"
echo "   ssh -i ${PRIVATE_KEY_PATH} -o IdentitiesOnly=yes ${TARGET_USER}@${REMOTE_HOST} \"curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh\""
echo
info "Remember to always connect using: ssh -i ${PRIVATE_KEY_PATH} -o IdentitiesOnly=yes ${TARGET_USER}@${REMOTE_HOST}"
echo 