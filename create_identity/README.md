# Bote identity generator

Simple script to generate Bote identity for use in **pboted**.   
The script reads the current contents of identities file, generates new identity and write to the same file.

Also, with parameter `--version 0` compatible with Java **I2P-Bote** decrypted identities file.

## Prepare

**I highly recommend making a backup copy of the identities file before running!**

For the script to work, version **Python** is required at least **3.8**
Before getting started, you will need to install the dependencies for each script:

```
pip3 install -r requirements.txt
```

## Parameters

- `-f` `--format` - Address formatting version (default: `1`)
- `-n` `--name` - The public name of the identity, included in emails
- `-a` `--algorithm` - Encryption and signature algorithm (default: `5`)
- `-i` `--image` - Path to image file
- `-d` `--description` - Description of the identity, only displayed locally.
- `-p` `--path` - Full path to current identities file (default: `identities.txt`)

## Example

Minimal:
```
./create_identity.py -n john_doe
```

Full case:
```
./create_identity.py -n john_doe -f 1 -a 2 -i /path/to/image.png -d "John main identity" -p /path/to/identities.txt
```
