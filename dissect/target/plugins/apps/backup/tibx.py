from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

try:
    from dissect.archive.tibx import find_split_parts

    from dissect.target.loaders.tibx import TibxLoader

    HAS_TIBX = True
except ImportError:
    HAS_TIBX = False

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

TibxRecoveryPointRecord = TargetRecordDescriptor(
    "application/backup/tibx/recovery_point",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_finished"),
        ("varint", "index"),
        ("string", "guid"),
        ("string", "type"),
        ("boolean", "selected"),
        ("boolean", "unfinished"),
        ("filesize", "size"),
        ("filesize", "compressed_size"),
        ("varint", "items_added"),
        ("varint", "items_changed"),
        ("varint", "items_removed"),
        ("string", "archive_uuid"),
        ("path", "source"),
    ],
)

TibxBackupRecord = TargetRecordDescriptor(
    "application/backup/tibx/backup",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_finished"),
        ("varint", "index"),
        ("string", "guid"),
        ("string", "type"),
        ("boolean", "latest"),
        ("boolean", "unfinished"),
        ("varint", "recovery_points"),
        ("boolean", "encrypted"),
        ("string", "archive_uuid"),
        ("path", "source"),
        ("path[]", "parts"),
    ],
)


class TibxPlugin(Plugin):
    """Acronis TIBX backup metadata of a target loaded from a TIBX archive.

    The ``tibx`` loader shows one backup of an archive per target. ``tibx.backup`` says which
    one, and ``tibx.recovery_points`` lists every backup in the archive as a timeline.
    """

    __namespace__ = "tibx"

    def __init__(self, target: Target):
        super().__init__(target)
        self.loader = target._loader if HAS_TIBX and isinstance(target._loader, TibxLoader) else None

    def check_compatible(self) -> None:
        if self.loader is None:
            raise UnsupportedPluginError("Target was not loaded from a TIBX archive")

    @export(record=TibxRecoveryPointRecord)
    def recovery_points(self) -> Iterator[TibxRecoveryPointRecord]:
        """Yield every backup in the archive, oldest first, the way ``acrocmd list backups`` lists them.

        The backup this target shows is ``selected``. A backup that has not finished, which
        ``acrocmd`` does not list, is listed too, as ``unfinished``; its data may be incomplete.

        Sizes and item counts are those the archive records for each backup, of its own data
        only, not that of the backups it builds on. Items are disks, partitions and Acronis
        metadata in a disk backup, files and directories in a file-level one.
        """
        tibx = self.loader.tibx
        selected = tibx.recovery_point
        archive_uuid = str(tibx.uuid)

        for point in tibx.recovery_points():
            yield TibxRecoveryPointRecord(
                ts_created=point.created,
                ts_finished=point.finished,
                index=point.index,
                guid=str(point.guid),
                type=point.type,
                selected=selected is not None and point.guid == selected.guid,
                unfinished=point.finished is None,
                size=point.size,
                compressed_size=point.compressed_size,
                items_added=point.items_added,
                items_changed=point.items_changed,
                items_removed=point.items_removed,
                archive_uuid=archive_uuid,
                source=self.loader.absolute_path or self.loader.path,
                _target=self.target,
            )

    @export(record=TibxBackupRecord)
    def backup(self) -> Iterator[TibxBackupRecord]:
        """Yield the backup this target shows, and the archive it is in.

        ``latest`` says whether it is the backup a target shows by default: the newest one
        that has finished, the newest one ``acrocmd list backups`` lists. ``unfinished`` says
        whether it is a backup that has not finished, whose data may be incomplete. The backup
        fields are empty if no backup in the archive has finished, and the target shows
        everything the archive holds.
        """
        tibx = self.loader.tibx
        points = tibx.recovery_points()
        point = tibx.recovery_point
        newest = next((candidate for candidate in reversed(points) if candidate.finished is not None), None)

        yield TibxBackupRecord(
            ts_created=point.created if point else None,
            ts_finished=point.finished if point else None,
            index=point.index if point else None,
            guid=str(point.guid) if point else None,
            type=point.type if point else None,
            latest=point is None or (newest is not None and point.guid == newest.guid),
            unfinished=point is not None and point.finished is None,
            recovery_points=len(points),
            encrypted=tibx.encrypted,
            archive_uuid=str(tibx.uuid),
            source=self.loader.absolute_path or self.loader.path,
            parts=find_split_parts(self.loader.absolute_path or self.loader.path),
            _target=self.target,
        )
