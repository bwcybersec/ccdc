#!/usr/bin/env bash

echo "Making disk..."
dd if=/dev/zero of=vault.disk bs=512 count=5000000  # approx. 256MB
cryptsetup luksFormat --hash=sha256 --key-size=256 --cipher=serpent-xts-plain64 --verify-passphrase vault.disk
cryptsetup luksOpen vault.disk vault
echo "Vault opened..."
mkfs.ext4 -L VAULT /dev/mapper/vault
mkdir /mnt/vault
mount /dev/mapper/vault /mnt/vault
echo "Success!"
