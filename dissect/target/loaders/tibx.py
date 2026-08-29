"""dissect.target loader for Acronis TIBX backup archives.

This is the only module in the package that imports ``dissect.target`` -- the parser
itself has no dependency on it, so it can later move into ``dissect.archive`` unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive.tibx.exceptions import (
    Error,
    InvalidPasswordError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.tibx import TIBX

from dissect.target.exceptions import LoaderError
from dissect.target.helpers import keychain
from dissect.target.loader import Loader
from dissect.target.volume import Volume

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

KEYCHAIN_PROVIDER = "tibx"


class TibxLoader(Loader):
    """Load Acronis TIBX (Cyber Protect / CyberBackup "archive3") backup archives.

    TIBX archives hold disk/partition image backups: each backed-up partition is a
    deduplicated, compressed data stream that is reconstructed lazily and mapped as a
    volume, letting filesystem and OS detection take over. Split archives
    (``Name-0001.tibx`` parts) are stitched automatically when the first part is opened.

    Encrypted archives take their password from the keychain (``-K`` / ``-Kv``).

    References:
        - https://github.com/mniedermaier/acronis-tibx (format documentation)
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        try:
            self.tibx = TIBX.open(path)
        except Error as e:
            raise LoaderError(f"Failed to open TIBX archive: {path}") from e

        # Recovery-point selection is available via the scheme form, e.g.
        # `target-query "tibx://path/backup.tibx?recovery-point=0"`
        recovery_point = self.parsed_query.get("recovery-point", "latest")
        try:
            self.tibx.use_recovery_point(recovery_point)
        except Error as e:
            raise LoaderError(f"Invalid recovery point for {path}: {e}") from e

        if self.tibx.encrypted:
            for key in keychain.get_keys_for_provider(KEYCHAIN_PROVIDER) + keychain.get_keys_without_provider():
                if key.key_type != keychain.KeyType.PASSPHRASE:
                    continue
                try:
                    self.tibx.unlock(key.value)
                    break
                except InvalidPasswordError:
                    continue
            else:
                raise LoaderError(f"Missing password for encrypted TIBX archive: {path}, use -K or -Kv")

    @staticmethod
    def detect(path: Path) -> bool:
        if path.suffix.lower() != ".tibx":
            return False
        try:
            with path.open("rb") as fh:
                header = fh.read(12)
        except OSError:
            return False
        return len(header) == 12 and header[0] == 0x41 and header[1] == 0x01 and header[8:12] == b"ARCH"

    def map(self, target: Target) -> None:
        try:
            for number, volume in enumerate(self.tibx.volumes(), start=1):
                target.volumes.add(
                    Volume(
                        volume.open(),
                        number=number,
                        offset=None,
                        size=volume.size,
                        vtype=None,
                        name=f"tibx_{volume.volume_id:x}",
                        raw=volume,
                    )
                )
        except UnsupportedFormatError as e:
            raise LoaderError(f"Unsupported TIBX feature in {self.path}") from e
