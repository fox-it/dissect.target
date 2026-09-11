from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive.tibx.c_tibx import PAGE_MARKER, c_tibx
from dissect.archive.tibx.exception import (
    Error,
    InvalidPasswordError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.page import ARCH_MAGIC
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
    """Load Acronis TIBX (Cyber Protect / True Image "archive3") backup archives.

    TIBX archives hold disk/partition image backups: each backed-up partition is a
    deduplicated, compressed data stream that is reconstructed lazily and mapped as a
    volume, letting filesystem and OS detection take over. The metadata streams Acronis
    stores alongside the partitions are not mapped. Split archives and backup chains
    (``Name-0001.tibx``, ...) are stitched automatically when the first file is opened.

    An archive can hold several backups, e.g. a full backup followed by incrementals. The
    latest is loaded by default. Select another with the ``recovery-point`` query parameter:
    its index counting from 0, in the order ``acrocmd list backups`` prints them (oldest
    first), or ``oldest`` / ``latest``::

        target-query -f hostname "tibx://path/to/backup.tibx?recovery-point=0"

    Encrypted archives take their password from the keychain (``-K`` / ``-Kv``).

    References:
        - https://github.com/TreadingTheTiber/acronis-tib-reader
        - acronis-tibx by mniedermaier (MIT, no longer publicly available), see
          ``THIRD_PARTY_NOTICES.md`` in ``dissect.archive``
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        try:
            self.tibx = TIBX.open(path)
        except Error as e:
            raise LoaderError(f"Failed to open TIBX archive: {path}") from e

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
                superblock = c_tibx.arch_superblock(fh)
        except (OSError, EOFError):
            return False
        return (
            superblock.header.marker == PAGE_MARKER
            and superblock.header.type == c_tibx.PageType.ARCH
            and superblock.body.magic == ARCH_MAGIC
        )

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
