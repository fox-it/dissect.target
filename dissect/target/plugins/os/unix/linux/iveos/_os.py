from __future__ import annotations

import re
import struct
from io import SEEK_END
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.crypto.util import xor
from dissect.util.stream import AlignedStream
from dissect.volume.disk import Partition
from dissect.volume.lvm.metadata import LogicalVolume

from dissect.target import filesystem
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.cpio import CpioFilesystem
from dissect.target.helpers.keychain import KeyType, register_key
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.volume import is_encrypted, open_encrypted

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

    try:
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

try:
    from Crypto.Cipher import AES

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# Ivanti AES keys to decrypt coreboot files that boot the device.
IVE_OS_KEYS: dict[str, bytes] = {
    "22.3R1": bytes.fromhex("ec14f9fac57e45699a525475e316d2df"),
    "22.6R2.1": bytes.fromhex("44f8f92165d65ab7a7b48e5bb810aa4f"),
    "22.7R2.9": bytes.fromhex("f85d4c06951800b8cffb3f7f1fd2c6f4"),
    "22.7R2.10": bytes.fromhex("8a0098fc8e0cf1a5fbad0ef69030f1d0"),
}

# Mappings for installation LVM groups, mapping an LVM volume name to the tuple source and target
# mount directory. groupA and groupB are the actual OS installations, while groupZ is the factory
# reset installation.
INSTALLATION_LVM_VOLUME_MAP = {
    "groupA": {
        "groupA-home": ("/root", "/"),
        "groupA-runtime": ("/", "/data"),
    },
    "groupB": {
        "groupB-home": ("/root", "/"),
        "groupB-runtime": ("/", "/data"),
    },
    "groupZ": {
        "groupZ-home": ("/", "/"),
    },
}

# Boot device map that maps for a given group the boot device to the tuple source and target mount
# directory.
BOOT_DEVICE_MAP = {
    "groupA": ("/dev/sda2", "/", "/boot"),
    "groupB": ("/dev/sda3", "/", "/boot"),
    "groupZ": ("/dev/sda1", "/", "/boot"),
}


def get_pvs(logical_volume: LogicalVolume) -> list[str]:
    """Retrieves the physical volumes linked to a logical volume in LVM.

    Args:
        logical_volume (LogicalVolume): the logical volume to retrieve the physical volumes of.

    Returns:
        list[str]: the list of physical volumes in text.
    """
    return [pv.device for pv in logical_volume.volume_group.pv if pv.device]


def get_device_names(filesystem: Filesystem) -> list[str]:
    """Given a filesystem, it returns the device names linked to a filesystem's volume.

    Args:
        filesystem (Filesystem): filesystem to retrieve partitions of.

    Returns:
        list[str]: list of partition names.
    """
    if isinstance(filesystem.volume.raw, Partition):
        return [f"/dev/sda{filesystem.volume.raw.number}"]
    if isinstance(filesystem.volume.raw.raw, LogicalVolume):
        return get_pvs(filesystem.volume.raw.raw)

    raise ValueError("Unknown filesystem volume type found.")


class IvantiCorebootFile(AlignedStream):
    """Class to read from an Ivanti coreboot.img file that is AES-encrypted and contains the LUKS
    keys to decrypt the LVM logical volumes and boot the Ivanti device.
    """

    def __init__(self, fh: BinaryIO, key: bytes):
        if not HAS_CRYPTO:
            raise RuntimeError("No crypto module available")

        self.fh = fh
        self.key = key
        self.SECTOR_SIZE = 512
        self.BLOCK_SIZE = 16
        self.aes = AES.new(self.key, AES.MODE_ECB)

        self.size = self.fh.seek(0, SEEK_END)
        self.TOTAL_NR_SECTORS = int(self.size / self.SECTOR_SIZE)

        super().__init__(size=self.size, align=512)

    def _decrypt_sector(self, buf: bytes, sector_nr: int) -> bytes:
        """Decrypts a 512-byte-aligned sector based on its contents buf and the sector number
        sector_nr.

        Based on https://github.com/NorthwaveSecurity/lilo-pulse-secure-decrypt/.

        Args:
            buf (bytes): encrypted 512-byte sector.
            sector_nr (int): number of the sector, starting from 0.

        Returns:
            bytes: the decrypted buffer.
        """
        decrypted_buf = bytearray(512)
        iv = struct.pack("<QQ", sector_nr, 0)
        xor_result = bytearray(self.BLOCK_SIZE)

        pre_iv = self.aes.decrypt(iv)

        for i in range(0, self.SECTOR_SIZE, self.BLOCK_SIZE):
            xor(buf[i : i + self.BLOCK_SIZE], pre_iv, xor_result)
            next_iv = decrypted_step = bytes(xor_result)

            decrypted_step = self.aes.decrypt(decrypted_step)
            xor(decrypted_step, iv, xor_result)

            decrypted_step = bytes(xor_result)
            decrypted_buf[i : i + self.BLOCK_SIZE] = decrypted_step

            iv = next_iv

        return bytes(decrypted_buf)

    def _read(self, offset: int, length: int) -> bytes:
        """Read from Ivanti AES-encrypted buffer.

        Args:
            fh (BinaryIO): handle to the encrypted buffer.
            key (bytes): AES key.

        Returns:
            bytes: decrypted buffer.
        """
        # The sector number from which we start decrypting.
        sector_nr = int(offset / self.SECTOR_SIZE)
        start_remainder = offset % self.SECTOR_SIZE
        is_aligned = not bool(start_remainder)

        # We have to begin decrypting from the sector start.
        self.fh.seek(sector_nr * self.SECTOR_SIZE)

        bytes_read = 0
        decrypted_chunks = []

        # Take into account if the offset is not 512-byte aligned.
        if not is_aligned:
            # Last bytes that aren't sector-aligned are unencrypted.
            if offset >= self.TOTAL_NR_SECTORS * self.SECTOR_SIZE and offset < self.size:
                self.fh.seek(offset)
                return self.fh.read(length)

            sector = self.fh.read(self.SECTOR_SIZE)
            decrypted_sector = self._decrypt_sector(sector, sector_nr)
            sector_nr += 1

            if start_remainder + length <= self.SECTOR_SIZE:
                return decrypted_sector[start_remainder : start_remainder + offset]

            decrypted_chunks.append(decrypted_sector[start_remainder:])
            bytes_read += self.SECTOR_SIZE - start_remainder

        while bytes_read < length and sector_nr < self.TOTAL_NR_SECTORS:
            sector = self.fh.read(self.SECTOR_SIZE)
            decrypted_sector = self._decrypt_sector(sector, sector_nr)

            if length - bytes_read >= self.SECTOR_SIZE:
                decrypted_chunks.append(decrypted_sector)
                bytes_read += self.SECTOR_SIZE
            else:
                decrypted_chunks.append(decrypted_sector[: length - bytes_read])
                return b"".join(decrypted_chunks)

            sector_nr += 1

        # The last bytes aren't encrypted.
        if bytes_read < length:
            decrypted_chunks.append(self.fh.read(length - bytes_read))

        return b"".join(decrypted_chunks)


class IveOSPlugin(LinuxPlugin):
    """Plugin for Ivanti Connect Secure (ICS) devices. Underlying operating system is called IVE OS."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._version = None

    @classmethod
    def _get_luks_key(cls, target: Target, boot_filesystem: Filesystem, aes_key: bytes) -> bytes:
        """Retrieves the LUKS key from an Ivanti Connect Secure boot filesystem.

        Args:
            target (Target): the target we're analyzing.
            boot_filesystem (Filesystem): the boot filesystem that contains the encrypted coreboot image.
            aes_key (bytes): the AES key to decrypt the encrypted coreboot image.

        Raises:
            ValueError: if /coreboot.img does not exist.
            ValueError: If /etc/lvmkey does not exist.

        Returns:
            bytes: the LUKS key the boot_filesystem contains.
        """
        if not boot_filesystem.exists("/coreboot.img"):
            raise ValueError("Cannot find coreboot.img file on boot filesystem.")

        target.log.warning("Decrypting coreboot.img")

        coreboot_fh = IvantiCorebootFile(boot_filesystem.open("/coreboot.img"), aes_key)
        cpio_filesystem = CpioFilesystem(coreboot_fh)

        if not cpio_filesystem.exists("/etc/lvmkey"):
            raise ValueError("Cannot find LUKS key!")

        return cpio_filesystem.open("/etc/lvmkey").read()

    @classmethod
    def _mount_installation(
        cls, vfs: VirtualFilesystem, filesystems: list[Filesystem], root: str, group: str
    ) -> VirtualFilesystem:
        """Mounts the relevant filesystems into a virtual filesystem relative to the root for the provided group.

        IVE OS has LVM groups, which depending on the GRUB configuration can be active or not. This
        method mounts an installation of IVE OS relative to the provided root. Depending on whether
        a group is active, its partitions/logical volume names have to be mounted at different locations.

        Args:
            vfs (VirtualFilesystem): the virtual filesystem in which to mount the filesysystems.
            filesystems (list[Filesystem]): a list of filesystems to pick from.
            root (str): the directory to map the installation to.
            group (str): the name of the LVM group to mount.

        Returns:
            VirtualFilesystem: the virtual filesystem containing the mounted installations relative to root.
        """
        if group not in ["groupA", "groupB", "groupZ"]:
            raise ValueError(f"Group {group} is not valid.")

        device_mapping = INSTALLATION_LVM_VOLUME_MAP[group]
        boot_device_name, *boot_dirs = BOOT_DEVICE_MAP[group]

        for fs in filesystems:
            if boot_device_name in get_device_names(fs):
                source_dir, target_dir = boot_dirs
            elif lv_map := device_mapping.get(fs.volume.name):
                source_dir, target_dir = lv_map
            else:
                continue

            vfs.map_fs(f"{root}/{target_dir}", fs, source_dir)

        return vfs

    @classmethod
    def parse_version_file(cls, fh: BinaryIO) -> str:
        """Retrieves the version of the provided IVE OS version file.

        Args:
            fh (BinaryIO): the file handle of the VERSION file.

        Returns:
            str: the parsed version as a string.
        """

        def parse_export(export_text: str, variable_name: str) -> str:
            """Parses a list of export lines and retrieves the value `variable_name` is set to.

            Args:
                export_text (str): the export text to parse.
                variable_name (str): the variable name to retrieve the value of.

            Returns:
                str: the value of the variable name.
            """
            matches = re.findall(f'export {variable_name}="?([^\n"]+)"?', version_text)
            if not matches:
                raise ValueError(f"Cannot retrieve value of {variable_name}.")
            return matches[0]

        version_text = fh.read().decode()
        minor_version = parse_export(version_text, "DSREL_MINOR")
        major_version = parse_export(version_text, "DSREL_MAJOR")
        release_version = parse_export(version_text, "DSREL_COMMENT")

        return f"{major_version}.{minor_version}{release_version}"

    @classmethod
    def parse_grub_config(cls, grub_config: str) -> tuple[str | None, str | None, str | None]:
        """Parses an Ivanti GRUB configuration and retrieves the active installation group name,
        rollback installation group name, if available, and the factory reset group name.

        Args:
            grub_config (str): the GRUB configuration as a string.

        Returns:
            tuple[str, str | None, str]: three values for the active, rollback, and factory reset
            group names, respectively.
        """

        def parse_grub_menu_entry(grub_config: str, menu_entry_name: str) -> str | None:
            """Retrieves the group name of an IVE OS GRUB config, given the GRUB menu entry name.

            Args:
                grub_config (str): the GRUB configuration to parse.
                entry_name (str): the GRUB menu entry name.

            Returns:
                str | None: the parsed group name of the menu entry name or None.
            """
            group_matches = re.findall(
                f'menuentry "{menu_entry_name}" {{.+?system=([A-Z])', grub_config, flags=re.DOTALL
            )

            if len(group_matches) > 1:
                raise ValueError(f"Found multiple active installations for {menu_entry_name}!")

            if group_matches:
                return f"group{group_matches[0]}"
            return None

        active_group = parse_grub_menu_entry(grub_config, "Current")
        rollback_group = parse_grub_menu_entry(grub_config, "Rollback")
        factory_reset_group = parse_grub_menu_entry(grub_config, "Factory Reset")

        return active_group, rollback_group, factory_reset_group

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        """Detects whether the provided target is an Ivanti Connect Secure target.

        Args:
            target (Target): target to check.

        Returns:
            Filesystem | None: None if the target does not contain an Ivanti Connect Secure image,
            else the filesystem containing the IVE OS version file.
        """
        for fs in target.filesystems:
            # Tested on Ivanti Connect Secure virtual appliance.
            if fs.exists("/VERSION"):
                target.log.warning("Found IVE OS version file.")
                iveos_version = cls.parse_version_file(fs.open("/VERSION"))
                if iveos_version in IVE_OS_KEYS:
                    return fs
                target.log.error("Cannot find IVE OS decryption key for version %s", iveos_version)
        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        """Creates the Ivanti Connect Secure filesystem.

        Args:
            target (Target): the target pointing to an Ivanti Connect Secure image.
            sysvol (Filesystem): System filesystem.

        Returns:
            Self: an IVEOSPlugin object instantialized with a processed target.
        """
        ivanti_version = None
        active_group = rollback_group = factory_reset_group = None
        boot_filesystems = []

        # Retrieve boot filesystems and active, rollback and factory reset installations.
        for fs in target.filesystems:
            # Tested on Ivanti Connect Secure virtual appliance.
            if fs.exists("/VERSION"):
                boot_filesystems.append(fs)

            if fs.exists("/grub/grub.cfg"):
                grub_config = fs.open("/grub/grub.cfg").read().decode()
                active_group, rollback_group, factory_reset_group = cls.parse_grub_config(grub_config)

                if active_group is None:
                    target.log.warning("No active installation found!")
                elif active_group not in INSTALLATION_LVM_VOLUME_MAP:
                    target.log.warning("Active group %s is unknown!", active_group)

                if rollback_group is None:
                    target.log.warning("No rollback installation found!")
                if rollback_group not in INSTALLATION_LVM_VOLUME_MAP:
                    target.log.warning("Rollback group %s is unknown!", rollback_group)

                if factory_reset_group is None:
                    target.log.warning("No factor reset installation found!")
                elif factory_reset_group not in INSTALLATION_LVM_VOLUME_MAP:
                    target.log.warning("Reset group %s is unknown!", factory_reset_group)

        if not boot_filesystems:
            raise ValueError("Cannot find IVE OS boot partitions!")

        # Decrypt all coreboot.img files and retrieve the LUKS keys for all LVM volumes.
        for boot_filesystem in boot_filesystems:
            ivanti_version = cls.parse_version_file(boot_filesystem.open("/VERSION"))

            target.log.warning("Loading IVE OS boot partition for IVE OS version %s", ivanti_version)

            if ivanti_version is None:
                raise ValueError("Cannot determine IVE OS version.")

            decryption_key = IVE_OS_KEYS.get(ivanti_version)

            if decryption_key is None:
                raise ValueError("Cannot find decryption key for version %s", ivanti_version)

            target.log.warning("Using AES key %s", decryption_key.hex())

            luks_key = cls._get_luks_key(target, boot_filesystem, decryption_key)

            target.log.warning("Retrieved LUKS key with hex-encoded value %s", luks_key.hex())

            register_key(KeyType.PASSPHRASE, luks_key, provider="luks", is_wildcard=True)

        enc_volumes = [volume for volume in target.volumes if is_encrypted(volume)]
        filesystems = boot_filesystems

        for enc_volume in enc_volumes:
            for volume in open_encrypted(enc_volume):
                filesystems.append(filesystem.open(volume))

        vfs = VirtualFilesystem()

        if active_group:
            vfs = cls._mount_installation(vfs, filesystems, "/", active_group)

        if rollback_group:
            vfs = cls._mount_installation(vfs, filesystems, "/$fs$/rollback/", rollback_group)

        if factory_reset_group:
            vfs = cls._mount_installation(vfs, filesystems, "/$fs$/reset/", factory_reset_group)

        target.fs.mount("/", vfs)

        return cls(target)
