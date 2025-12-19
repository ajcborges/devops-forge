# 1Password Export Utility
1Password is a secure and user-friendly solution for managing credentials in a centralized location. Your data is stored safely in 1Password’s cloud infrastructure. However, as with any cloud-based service, it’s recommended to maintain periodic backups for disaster recovery. This utility helps you create a local export of your 1Password data in a directory of your choice.

## Installation

The script `1password-export.py` depends on:

- Python 3
- 1Password CLI integration

Follow the official guide at [1Password CLI Documentation](https://developer.1password.com/docs/cli/) to set up the CLI. 
The tool works best with 1Password version 8.


## Pre-Export Setup

On macOS, you can create a secure disk image for this purpose. Refer to Apple’s guide on creating a secure disk image for detailed steps.
For this guide, we assume you’ve created a disk image named Secure and mounted it at /Volumes/Secure.
Additionally, exclude this directory from Spotlight indexing for added privacy. Instructions can be found here.

## Running the Script

Execute the script using:

```
# 1Password CLI Version Check
$> op --version

# 1Password Account list
$> op account list

# 1Password current account
$> op whoami

# 1Password Athentication
$> op signin --account anz.1password.eu --raw

# 1Password current account
$> op whoami # 1Password current account

# run export script
$> python3 export_passwords.py --verbose # run export script
```

## What it does

- Exports items (default: LOGIN category only) from your 1Password vaults to a CSV.
- Tries to authenticate via:

  - Existing OP_SESSION_* or OP_SESSION env vars,
  - Interactive op signin --raw,
  - Account-qualified op signin --account <domain> --raw,
  - Or proceeds without --session if the desktop app is unlocked.

- Writes a CSV with columns: vault, item_title, username, password, url, item_id, category, tags.
- Sets the output file permissions to 0600.
