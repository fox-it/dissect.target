from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.archive.tibx.exception import (
    Error,
    InvalidPasswordError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.tibx import SPLIT_PART_RE, TIBX, find_split_parts

from dissect.target.exceptions import LoaderError
from dissect.target.helpers import keychain
from dissect.target.loader import Loader
from dissect.target.volume import Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

KEYCHAIN_PROVIDER = "tibx"

RECOVERY_POINT = "recovery-point"


class TibxLoader(Loader):
    """Load Acronis TIBX (Cyber Protect / True Image "archive3") backup archives.

    TIBX archives hold disk/partition image backups: each backed-up partition is a
    deduplicated, compressed data stream that is reconstructed lazily and mapped as a
    volume, letting filesystem and OS detection take over. The metadata streams Acronis
    stores alongside the partitions are not mapped. Split archives and backup chains
    (``Name-0001.tibx``, ...) are stitched automatically when the first file is opened.

    An archive can hold several backups, e.g. a full backup followed by incrementals. The
    latest is loaded by default: the newest backup that has finished, the newest one
    ``acrocmd list backups`` lists. Select another with the ``recovery-point`` query parameter:
    its index counting from 0, in the order ``acrocmd list backups`` prints them (oldest
    first), ``oldest`` / ``latest``, or its GUID::

        target-query -f hostname "tibx://path/to/backup.tibx?recovery-point=0"
        target-query -f hostname "tibx://path/to/backup.tibx?recovery-point=5ad78378-..."

    An index shifts once Acronis deletes older backups; a GUID keeps naming the same backup.

    A backup that has not finished, which ``acrocmd`` does not list, is loaded only when
    selected. Its data may be incomplete.

    The target's path names the backup it shows by GUID, as ``<archive>?recovery-point=<guid>``,
    the latest one included. So the ``_source`` of every record says which backup it came from,
    and ``tibx://`` in front of it opens that backup again.

    ``recovery-point=all`` opens one target per backup, oldest first, for the tools that open
    several targets, such as ``target-query``::

        target-query -f services "tibx:///vault/plc-eng01.tibx?recovery-point=all"

    The ``tibx`` plugin tells more about a target loaded from an archive: ``tibx.backup`` the
    backup it shows, and ``tibx.recovery_points`` every backup in the archive.

    Encrypted archives take their password from the keychain (``-K`` / ``-Kv``).
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        recovery_point = self.parsed_query.get(RECOVERY_POINT, "latest")
        if recovery_point == "all":
            raise LoaderError(
                f"{RECOVERY_POINT}=all opens one target per backup, which only tools that open several "
                f"targets do, such as target-query: {path}"
            )

        try:
            self.tibx = TIBX.open(path)
        except Error as e:
            raise LoaderError(f"Failed to open TIBX archive: {path}") from e

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
        # The later parts of a split archive are read through its first file
        return not SPLIT_PART_RE.match(path.name) or find_split_parts(path)[0] == path

    @staticmethod
    def find_all(path: Path, parsed_path: urllib.parse.ParseResult | None = None) -> Iterator[str | Path]:
        """With ``recovery-point=all``, yield a URI for every backup in the archive, oldest first.

        Those are the backups ``tibx.recovery_points`` lists, a backup that has not finished
        included. Each URI keeps the query it was given, with the backup's GUID for
        ``recovery-point``. Otherwise, or if the archive cannot be opened here, yield ``path``
        itself, so that loading it reports the problem the way it does for any other target.
        """
        query = dict(urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True)) if parsed_path else {}
        if query.get(RECOVERY_POINT) != "all":
            yield path
            return

        try:
            with TIBX.open(path) as tibx:
                selectors = [str(point.guid) for point in tibx.recovery_points()]
        except Error:
            yield path
            return

        # An archive that records no backups still has its live state to show
        for selector in selectors or ["latest"]:
            query[RECOVERY_POINT] = selector
            yield f"{parsed_path.scheme}://{parsed_path.netloc}{parsed_path.path}?{urllib.parse.urlencode(query)}"

    def map(self, target: Target) -> None:
        # The latest backup today is not the latest tomorrow, so the path names the backup
        # by GUID even when the latest is loaded by default
        if (point := self.tibx.recovery_point) is not None:
            target.path = Path(f"{self.path}?{RECOVERY_POINT}={point.guid}")

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
