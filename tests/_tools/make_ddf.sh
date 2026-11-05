#!/usr/bin/env bash
#
# Generate the 2-disk DDF (SNIA Disk Data Format) RAID1 fixture for the DdfVolumeSystem tests.
#
# Produces two gzipped raw physical-disk images (ddf-disk0.bin.gz, ddf-disk1.bin.gz) that
# together form a single DDF container with one RAID1 virtual disk containing a small ext2
# filesystem with a known file. This exercises DdfVolumeSystem.open_all([disk0, disk1]),
# including the multi-disk `disk` list handling.
#
# Must be run as root (losetup + mdadm), e.g.:
#
#     sudo tests/_tools/make_ddf.sh
#
# By default the fixtures are written to tests/_data/volumes/ddf/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/../_data/volumes/ddf}"
DISK_SIZE="${2:-33554432}"  # 32 MiB per disk

WORK="$(mktemp -d)"
DISK0="${WORK}/disk0.img"
DISK1="${WORK}/disk1.img"
MNT="${WORK}/mnt"

CONTAINER="/dev/md/ddf_fixture_container"
VOLUME="/dev/md/ddf_fixture_volume"

LOOP0=""
LOOP1=""

cleanup() {
    set +e
    mountpoint -q "${MNT}" 2>/dev/null && umount "${MNT}"
    mdadm --stop "${VOLUME}" 2>/dev/null
    mdadm --stop "${CONTAINER}" 2>/dev/null
    [ -n "${LOOP0}" ] && losetup -d "${LOOP0}" 2>/dev/null
    [ -n "${LOOP1}" ] && losetup -d "${LOOP1}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${MNT}"

# Sparse backing files
truncate -s "${DISK_SIZE}" "${DISK0}"
truncate -s "${DISK_SIZE}" "${DISK1}"

LOOP0="$(losetup -f --show "${DISK0}")"
LOOP1="$(losetup -f --show "${DISK1}")"
echo "loop0=${LOOP0} loop1=${LOOP1}"

# Create a DDF container spanning both disks, then a RAID1 virtual disk inside it.
mdadm --create "${CONTAINER}" --run --raid-devices=2 --metadata=ddf "${LOOP0}" "${LOOP1}"
mdadm --create "${VOLUME}" --run --raid-devices=2 --level=1 "${CONTAINER}"

# Wait for initial resync to settle
mdadm --wait "${VOLUME}" || true

# Put a tiny known filesystem on the virtual disk
mkfs.ext2 -q -L ddf_fixture "${VOLUME}"
mount "${VOLUME}" "${MNT}"
echo -n "wow it worked" > "${MNT}/file.txt"
sync
umount "${MNT}"

# Cleanly stop the arrays so DDF metadata is flushed to the backing disks
mdadm --stop "${VOLUME}"
mdadm --stop "${CONTAINER}"
losetup -d "${LOOP0}"; LOOP0=""
losetup -d "${LOOP1}"; LOOP1=""

mkdir -p "${OUT_DIR}"
gzip -9 -c "${DISK0}" > "${OUT_DIR}/ddf-disk0.bin.gz"
gzip -9 -c "${DISK1}" > "${OUT_DIR}/ddf-disk1.bin.gz"

# Ensure the resulting fixtures are owned by the invoking user, not root
if [ -n "${SUDO_UID:-}" ]; then
    chown "${SUDO_UID}:${SUDO_GID:-${SUDO_UID}}" "${OUT_DIR}/ddf-disk0.bin.gz" "${OUT_DIR}/ddf-disk1.bin.gz"
fi

ls -l "${OUT_DIR}/ddf-disk0.bin.gz" "${OUT_DIR}/ddf-disk1.bin.gz"
echo "DONE"
