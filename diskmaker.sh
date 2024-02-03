#!/usr/bin/env bash

dd if=/dev/zero of=vault.disk bs=8192 count=1000000 status=progress  # approx. 8GB
cryptsetup luksFormat --hash=sha256 --key-size=256 --cipher=aes-xts-plain64 --verify-passphrase vault.disk
cryptsetup luksOpen vault.disk vault
mkfs.ext4 -L VAULT /dev/mapper/vault
mount -m /dev/mapper/vault /mnt/vault
echo "Success!"
