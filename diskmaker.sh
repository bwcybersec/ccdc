#!/usr/bin/env bash

dd if=/dev/zero of=vault.disk bs=8192 count=1000000  # approx. 8GB
cryptsetup luksFormat --hash=sha256 --key-size=256 --cipher=serpent-xts-plain64 --verify-passphrase vault.disk
cryptsetup luksOpen vault.disk vault
echo "Vault opened..."
mkfs.ext4 -L VAULT /dev/mapper/vault
mkdir /mnt/vault
mount /dev/mapper/vault /mnt/vault
echo "Success!"
