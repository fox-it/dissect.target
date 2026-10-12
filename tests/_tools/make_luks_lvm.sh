#!/usr/bin/env bash
#
# Generate the LUKS-over-LVM fixture for the scrape plugin integration tests.
#
# Produces a single gzipped raw disk image (luks-lvm.bin.gz) laid out as:
#
#     disk (GPT) -> partition 1 -> LUKS2 -> LVM (PV/VG/LV) -> ext2 -> file.txt
#
# This exercises the scraper's ability to resolve a decrypted (LUKS) layer *and* a nested logical
# volume (LVM) down to the correct physical regions on disk. The ext2 filesystem contains a single
# known file with the marker "wow it worked".
#
# The LUKS keyslot deliberately uses PBKDF2 (instead of the default argon2id) so unlocking the
# fixture in tests is fast and low-memory, and so it only depends on the Python stdlib `hashlib`
# in dissect.fve rather than the optional argon2 backend.
#
# The passphrase is fixed (see PASSPHRASE below); the scrape test must use the same value.
#
# Must be run as root (losetup + cryptsetup + LVM), e.g.:
#
#     sudo tests/_tools/make_luks_lvm.sh
#
# By default the fixture is written to tests/_data/volumes/luks_lvm/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/../_data/volumes/luks_lvm}"
DISK_SIZE="${2:-8388608}"  # 8 MiB

PASSPHRASE="password1234"
MAPPER="luks_lvm_fixture"
VG="luks_lvm_vg"
LV="luks_lvm_lv"

WORK="$(mktemp -d)"
DISK="${WORK}/disk.img"
MNT="${WORK}/mnt"

LOOP=""

cleanup() {
    set +e
    mountpoint -q "${MNT}" 2>/dev/null && umount "${MNT}"
    vgchange -an "${VG}" 2>/dev/null
    cryptsetup status "${MAPPER}" >/dev/null 2>&1 && cryptsetup luksClose "${MAPPER}"
    [ -n "${LOOP}" ] && losetup -d "${LOOP}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${MNT}"

# Sparse backing file
truncate -s "${DISK_SIZE}" "${DISK}"

# Attach with partition scanning enabled so /dev/loopXp1 appears
LOOP="$(losetup -f -P --show "${DISK}")"
echo "loop=${LOOP}"

# GPT with a single partition starting at 1 MiB (non-zero offset makes the offset resolution meaningful)
parted -s "${LOOP}" mklabel gpt
parted -s "${LOOP}" mkpart primary 1MiB 100%
partprobe "${LOOP}"
udevadm settle 2>/dev/null || true

PART="${LOOP}p1"

# LUKS2 with a cheap PBKDF2 keyslot. --force-password disables a possible pwquality dictionary
# check so the simple fixed test passphrase is accepted in batch mode. A small keyslot area and 1 MiB
# data offset keep the (incompressible, encrypted) fixture small.
printf '%s' "${PASSPHRASE}" | cryptsetup luksFormat \
    --type luks2 \
    --pbkdf pbkdf2 \
    --pbkdf-force-iterations 1000 \
    --luks2-keyslots-size 512KiB \
    --offset 2048 \
    --force-password \
    --batch-mode \
    "${PART}"
printf '%s' "${PASSPHRASE}" | cryptsetup luksOpen "${PART}" "${MAPPER}"

# LVM inside the decrypted volume. A small metadata area keeps the encrypted footprint down.
pvcreate -f --metadatasize 128k "/dev/mapper/${MAPPER}"
vgcreate "${VG}" "/dev/mapper/${MAPPER}"
lvcreate -l 100%FREE -n "${LV}" "${VG}"

# Put a tiny known filesystem on the logical volume. Minimal metadata (no resize inode, few inodes)
# keeps the encrypted, incompressible footprint of the fixture small.
mkfs.ext2 -q -O ^resize_inode -N 32 -L luks_lvm "/dev/${VG}/${LV}"
mount "/dev/${VG}/${LV}" "${MNT}"
echo -n "wow it worked" > "${MNT}/file.txt"
sync
umount "${MNT}"

# Cleanly tear down so all metadata is flushed to the backing disk
vgchange -an "${VG}"
cryptsetup luksClose "${MAPPER}"
losetup -d "${LOOP}"; LOOP=""

mkdir -p "${OUT_DIR}"
gzip -9 -c "${DISK}" > "${OUT_DIR}/luks-lvm.bin.gz"

# Ensure the resulting fixture is owned by the invoking user, not root
if [ -n "${SUDO_UID:-}" ]; then
    chown "${SUDO_UID}:${SUDO_GID:-${SUDO_UID}}" "${OUT_DIR}/luks-lvm.bin.gz"
fi

ls -l "${OUT_DIR}/luks-lvm.bin.gz"
echo "DONE"
