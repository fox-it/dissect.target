from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target import filesystem
from dissect.target.exceptions import FilesystemError
from dissect.target.helpers import configutil
from dissect.target.helpers.record import EmptyRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

try:
    from dissect.target.helpers.fscrypt import FSCrypt
    from dissect.target.plugins.os.unix.linux.android.lock.xts import (
        XTSDecryptionStream,
    )

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

METADATA_ENCRYPTION_KEY_PATH = "vold/metadata_encryption/key/"

VOLUME_MAPPINGS = {
    "system": "/",
    "product": "/product",
    "vendor": "/vendor",
    "system_ext": "/system_ext",
    "userdata": "/data",
    "metadata": "/metadata",
}

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class AndroidPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

        self.userdata_partition_unlocked = False
        self.device_encrypted_storage_unlocked = False
        self.credential_encrypted_storage_unlocked = False
        self.unlock()

        self.build_prop_paths = set(find_build_props(self.target.fs))
        self.props = {}

        for build_prop in self.build_prop_paths:
            try:
                self.props.update(
                    configutil.parse(
                        build_prop,
                        hint="meta_bare",
                        separator=("=",),
                        comment_prefixes=("#",),
                    ).parsed_data
                )
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Unable to parse Android build.prop file %s: %s", build_prop, e)

    def _unlock_userdata_partition(self) -> bool:
        """Using the key material from the metadata partition, wrap the userdata partition's file handle in a decryption
        stream."""
        if self.userdata_partition_unlocked:
            return True

        userdata_volume = next((vol for vol in self.target.volumes if vol.name == "userdata"), None)

        # To be able to decrypt the device-encrypted or credential-encrypted storage the userdata partition must be
        # decrypted first
        if not self.target.fs.exists("/metadata"):
            self.target.log.error("Metadata filesystem is required to unlock userdata partition")
            return False
        if not HAS_CRYPTO:
            self.target.log.error("dissect.fve is required to decrypt the userdata partition")
            return False

        metadata_path = self.target.fs.path("/metadata").joinpath(METADATA_ENCRYPTION_KEY_PATH)
        metadata_decryption_key = self.target.keystore.retrieve_key(metadata_path)
        userdata_volume.fh = XTSDecryptionStream(userdata_volume.fh, metadata_decryption_key, userdata_volume.size)

        try:
            fs = filesystem.open(userdata_volume.fh)
        except FilesystemError:
            self.target.log.exception("Unable to open filesystem on decrypted userdata partition")
            # Technically, the partition has been unlocked. We just can't the filesystem contained within it
            return True

        userdata_volume.fs = fs
        self.target.filesystems.add(fs)
        self.target.fs.mount("/data", fs)
        self.userdata_partition_unlocked = True
        return True

    def _unlock_device_encrypted_storage(self) -> bool:
        """Requires a decryption of the userdata partition. Add FSCrypt to the userdata filesystem and add key material
        from paths owned by system."""
        if self.device_encrypted_storage_unlocked:
            return True

        userdata_volume = next((vol for vol in self.target.volumes if vol.name == "userdata"), None)

        encrypted_fh = userdata_volume.fh.fh
        fscrypt = FSCrypt(encrypted_fh)
        userdata_fs = userdata_volume.fs
        method = getattr(userdata_fs, "add_fscrypt", None)
        if method is None or not callable(method):
            # This could happen if Dissect were to support F2FS without implementing fscrypt support for it
            raise ValueError("Volume with userdata must have a filesystem implementation that supports fscrypt")
        userdata_fs.add_fscrypt(fscrypt)

        # The metadata key is used for file-based encryption to protect device-encrypted storage
        metadata_path = self.target.fs.path("/metadata").joinpath(METADATA_ENCRYPTION_KEY_PATH)
        metadata_decryption_key = self.target.keystore.retrieve_key(metadata_path)
        userdata_fs.fscrypt.add_key(metadata_decryption_key)

        try:
            # https://cs.android.com/android/platform/superproject/main/+/main:system/vold/FsCrypt.cpp

            # The 'device key': no other folders can be opened before this key is added
            key = self.target.keystore.retrieve_key(userdata_fs.path("/unencrypted/key"))
            userdata_fs.fscrypt.add_key(key)

            # The 'device encryption key' for a given user
            key = self.target.keystore.retrieve_key(userdata_fs.path("/misc/vold/user_keys/de/0"))
            userdata_fs.fscrypt.add_key(key)

            self.device_encrypted_storage_unlocked = True
        except Exception:
            self.target.log.exception(
                "Unable to decrypt device-encrypted storage. Cannot decrypt credential-encrypted storage"
            )
            return False

        self.device_encrypted_storage_unlocked = True
        return True

    def _unlock_credential_encrypted_storage(self) -> bool:
        """Requires a decryption of the userdata partition and device-encrypted storage. Try to decrypt the synthetic
        password and add the resulting key to fscrypt."""
        if self.credential_encrypted_storage_unlocked:
            return True

        userdata_volume = next((vol for vol in self.target.volumes if vol.name == "userdata"), None)
        userdata_fs = userdata_volume.fs
        fscrypt = userdata_fs.fscrypt
        if fscrypt is None:
            raise ValueError(
                "Volume with userdata must have fscrypt initialized to unlock credential-encrypted storage"
            )
        method = getattr(userdata_fs, "add_fscrypt", None)
        if method is None or not callable(method):
            # This could happen if Dissect were to support F2FS without implementing fscrypt support for it
            raise ValueError("Volume with userdata must have a filesystem implementation that supports fscrypt")

        # Finally, try to unlock the credential-encrypted storage
        try:
            fscrypt.add_key(self.target.synthetic_password_manager.get_credential_encryption_key())
            self.credential_encrypted_storage_unlocked = True
        except Exception as e:
            self.target.log.warning("Unable to decrypt credential-encrypted storage: %s", e)
        return self.credential_encrypted_storage_unlocked

    def unlock(self) -> bool:
        """Unlock the Android device storage. This is a multi-step process:
            1. Decrypt the userdata partition using the key material from the metadata partition
            2. Decrypt the device-encrypted storage using key material stored on the userdata partition
            3. Decrypt the credential-encrypted storage using key material derived from the user's credentials

        Resources:
            - https://blog.quarkslab.com/android-data-encryption-in-depth.html
            - https://github.com/SlugFiller/fbe-decrypt
            - https://android.stackexchange.com/questions/217019/what-is-a-synthetic-password-and-how-is-it-used-by-android
        """
        if not self._unlock_userdata_partition():
            return False
        if not self._unlock_device_encrypted_storage():
            return False
        return self._unlock_credential_encrypted_storage()

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        ANDROID_PATHS = (
            "data",
            "system",
            "vendor",
            "product",
        )
        userdata_fs = None
        metadata_fs = None
        for fs in target.filesystems:
            if all(fs.exists(p) for p in ANDROID_PATHS) and any(find_build_props(fs)):
                return fs
            if fs.exists("/unencrypted") and fs.exists("misc"):
                userdata_fs = fs

            # The userdata partition can be full-volume encrypted (with the metadata partition having the decryption
            # key), so as a fallback we want to detect based on the metadata partition
            if fs.exists(METADATA_ENCRYPTION_KEY_PATH):
                metadata_fs = fs
        # Prefer userdata_fs if both are found
        return userdata_fs if userdata_fs else metadata_fs

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        # NOTE: When system partitions cannot be opened, the volume will not be successfully opened and fs will be None.
        # We skip mounting such volumes.
        for volume in target.volumes:
            if volume.name in VOLUME_MAPPINGS and volume.fs is not None:
                target.fs.mount(VOLUME_MAPPINGS[volume.name], volume.fs)
        else:
            # No volumes: probably a virtual target
            target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        return self.props.get("ro.build.host")

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> str:
        full_version = "Android"

        release_version = self.props.get("ro.build.version.release")
        if release_version := self.props.get("ro.build.version.release"):
            full_version += f" {release_version}"

        if security_patch_version := self.props.get("ro.build.version.security_patch"):
            full_version += f" ({security_patch_version})"

        return full_version

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ANDROID.value

    @export(record=EmptyRecord)
    def users(self) -> Iterator[EmptyRecord]:
        yield from ()


def find_build_props(fs: Filesystem) -> Iterator[Path]:
    """Search for Android ``build.prop`` files on the provided :class:`Filesystem`."""
    if (root_prop := fs.path("/build.prop")).is_file():
        yield root_prop

    for prop in fs.path("/").glob("*/build.prop"):
        if prop.is_file():
            yield prop
