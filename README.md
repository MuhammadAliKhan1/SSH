# Initial Ubuntu Server Setup Script

This script automates the essential security and configuration steps for a new Ubuntu server. It is designed to take a fresh, unconfigured server and apply baseline security best practices, making it ready for use.

## Features

This script will guide you through the following steps for an **existing user with sudo privileges**:

1.  **Configure UFW Firewall**: Sets up the Uncomplicated Firewall (UFW) to allow SSH, HTTP, and HTTPS traffic.
2.  **Set Up SSH Key-Based Authentication**:
    *   Generates a new 4096-bit RSA key pair on your local machine if one doesn't exist.
    *   Copies your public key to the user on the remote server, enabling secure, passwordless logins.
3.  **Harden SSH Security**:
    *   Disables direct root login (`PermitRootLogin no`).
    *   Disables password-based authentication (`PasswordAuthentication no`), forcing all connections to use SSH keys.

## Prerequisites

-   An Ubuntu server (tested on 20.04/22.04).
-   The IP address of the server.
-   A pre-existing user account on the server with `sudo` (administrative) privileges.
-   The password for that user account.

## How to Use

1.  **Clone or Download the Script**:
    Get the `setup_server.sh` script onto your local machine.

2.  **Make the Script Executable**:
    Open your terminal and run the following command to grant execute permissions to the script:
    ```bash
    chmod +x setup_server.sh
    ```

3.  **Run the Script**:
    Execute the script from your terminal:
    ```bash
    ./setup_server.sh
    ```

4.  **Follow the Prompts**:
    The script is interactive and will prompt you for necessary information:
    *   The server's IP address.
    *   Your username on the server.

    It will then ask for your user's password to connect and run the necessary `sudo` commands.

## Security Warning

-   This script makes significant security changes to your server, including disabling root login and password authentication.
-   **CRITICAL**: Before you allow the script to disable password authentication, ensure you have successfully tested logging in with your new user and SSH key (`ssh new_user@your_server_ip`). If you do not, you may lock yourself out of your server.
-   The script will back up your original SSH configuration file to `/etc/ssh/sshd_config.bak` on the server before making changes.

## Connecting to Your Server

After successfully running the script, your server is configured to only accept connections using your SSH key.

### Your SSH Key Location

The script uses your default SSH key. On your **local machine**, you can find your keys at:
-   **Private Key**: `~/.ssh/id_rsa` (Keep this secret!)
-   **Public Key**: `~/.ssh/id_rsa.pub` (This is what was copied to the server)

### Basic Connection Command

To connect to your server, open a terminal on your local machine and use the following command, replacing `your_user` and `your_server_ip` with the values you used in the script:

```bash
ssh your_user@your_server_ip
```

### Using an SSH Config File (Recommended)

For a much easier and more organized way to connect, you can add an entry to your local SSH config file at `~/.ssh/config`. This is also what tools like the VS Code and Cursor remote SSH extensions use.

1.  **Open or create the config file**:
    ```bash
    nano ~/.ssh/config
    ```

2.  **Add the following block** to the file, replacing the placeholder values:

    ```ini
    # A memorable name for your VM connection
    Host YourVMAlias

        # The IP address of your server
        HostName your_server_ip

        # The user you created on the server
        User your_user

        # The path to your private key
        IdentityFile ~/.ssh/id_rsa

        # CRITICAL for users with many keys in an SSH Agent
        # This forces SSH to use only the key specified above.
        IdentitiesOnly yes

        # (Optional) Specify the port if it's not the default 22
        # Port 22
    ```

3.  **Save and Exit** (`CTRL + X`, then `Y`, then `Enter`). Make sure the permissions on this file are secure by running `chmod 600 ~/.ssh/config`.

Now, you can connect to your server with a simple command:
```bash
ssh YourVMAlias
```

And when using a remote SSH extension in VS Code or Cursor, you can simply tell it to connect to the host `YourVMAlias`.

### Connecting with a Password (For Remote Development)

If key-based authentication is failing and you need to connect to your server to work or troubleshoot, you can use this configuration. It will force the SSH client to use password authentication.

Add the following to your `~/.ssh/config` file:

```ini
# A memorable name for your VM connection (Password Auth)
Host YourVMAlias-password

    # The IP address of your server
    HostName your_server_ip

    # The user you created on the server
    User your_user

    # Force password-based authentication methods
    PubkeyAuthentication no
    PreferredAuthentications keyboard-interactive,password
```

You can then connect in your terminal with `ssh YourVMAlias-password` or use the host `YourVMAlias-password` in your remote SSH extension.

## Manual Setup Guide

If the script fails, you can perform the steps manually. This guide assumes you can connect to your server with a password.

1.  **Generate a Key (Local Machine)**:
    If you don't have one, create an SSH key on your local computer.
    ```bash
    ssh-keygen -t rsa -b 4096
    ```

2.  **Copy the Key to the Server (Local Machine)**:
    Use `ssh-copy-id` to securely transfer your public key.
    ```bash
    ssh-copy-id your_user@your_server_ip
    ```

3.  **Fix Permissions (On the Server)**:
    SSH into your server with your password and run these commands to ensure the permissions are correct. This is the most common point of failure.
    ```bash
    # Run these commands ON THE SERVER
    chmod go-w ~
    chmod 700 ~/.ssh
    chmod 600 ~/.ssh/authorized_keys
    ```

4.  **Test the Key (Local Machine)**:
    Open a **new terminal** and try to connect using only your key. If it connects without asking for a password, you have succeeded.
    ```bash
    ssh -i ~/.ssh/id_rsa -o IdentitiesOnly=yes your_user@your_server_ip
    ```

5.  **Harden the Server (On the Server)**:
    Once you have confirmed your key works, SSH into your server one last time and disable password logins.
    ```bash
    # Run these commands ON THE SERVER
    sudo nano /etc/ssh/sshd_config

    # Find and change these lines to 'no':
    # PermitRootLogin no
    # PasswordAuthentication no

    # Save the file (CTRL+X, Y, Enter) and restart the SSH service:
    sudo systemctl restart ssh
    ```

## Troubleshooting

Here are solutions to common issues you might encounter.

### Error: `Too many authentication failures` When Connecting Manually

If the script succeeds but you cannot connect with a simple `ssh user@host` command, it is almost always because you have an SSH Agent running with multiple keys. The server sees these as multiple failed login attempts and disconnects you.

**Solution:**
You must be explicit in your connection command or your `~/.ssh/config` file.

1.  **Command Line**: Use the `IdentitiesOnly=yes` option to force SSH to use only the key you specify.
    ```bash
    ssh -i /path/to/your/private_key -o IdentitiesOnly=yes user@host
    ```

2.  **SSH Config (Recommended)**: Add `IdentitiesOnly yes` to the host entry in your `~/.ssh/config` file. See the example in the "Connecting to Your Server" section above.

### Error: `Permission denied (publickey)`

This is the most common error and it almost always means there is a **file permissions issue on the server**. The SSH daemon is very strict and will reject a key if your home directory or `.ssh` folder is not secure.

**Solution:**
You must log in to your server using a direct console (e.g., via your VM provider's web interface, RDP, VirtualBox, etc.) and run these commands to fix the permissions. Replace `your_user` with the actual username.

```bash
# Fix home directory permissions (removes write access for group/other)
chmod go-w /home/your_user

# Fix .ssh directory permissions (only owner can access)
chmod 700 /home/your_user/.ssh

# Fix authorized_keys file permissions (only owner can read/write)
chmod 600 /home/your_user/.ssh/authorized_keys
```

### How to Reset SSH Access (If You Get Locked Out)

If you accidentally lock yourself out of your server (e.g., by running the script and then realizing your SSH key doesn't work), you can regain access by temporarily re-enabling password authentication.

**You must use a direct console to the server to perform these steps.**

1.  **Log in via Console and Gain Root Access**:
    Open a terminal on your VM's console and elevate your privileges to `root`.
    ```bash
    sudo -i
    ```

2.  **Edit the SSH Configuration File**:
    Open the main SSH config file with a text editor like `nano`.
    ```bash
    nano /etc/ssh/sshd_config
    ```

3.  **Re-enable Password Logins**:
    Inside the editor, find these two lines. Make sure they are not commented out (i.e., they do not start with `#`) and set their values to `yes`.
    ```ini
    PermitRootLogin yes
    PasswordAuthentication yes
    ```

4.  **Save and Exit**:
    *   Press `CTRL + X`.
    *   Press `Y` to confirm you want to save.
    *   Press `Enter` to write the changes to the file.

5.  **Restart the SSH Service**:
    This final command applies your changes.
    ```bash
    systemctl restart ssh
    ```

Your server will now accept password-based logins again, allowing you to re-run the script or manually fix any issues. 