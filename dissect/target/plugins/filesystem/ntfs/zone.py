from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.ntfs.util import segment_reference

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.ntfs.mft import _Info
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs import MftRecord
    from dissect.ntfs.attr import Attribute, FileName, StandardInformation
    from flow.record import Record
    from typing_extensions import Self

    from dissect.target.filesystems.ntfs import NtfsFilesystem
    from dissect.target.target import Target

    
ZoneIdentifierRecord = TargetRecordDescriptor(
    "filesystem/ntfs/ads/zone_identifier",
    [
        ("uint32", "zone_id"),
        ("string", "referrer_url"),
        ("string", "host_url"),
        ("path", "file_path"),
        ("string", "volume_uuid"),
    ],
)


class ZoneIdPlugin(Plugin):
    """NFTS UsnJrnl plugin."""
    __namespace__ = "zone"

    def __init__(self, target: Target):
        super().__init__(target)
        self.ntfs_filesystems = {index: fs for index, fs in enumerate(self.target.filesystems) if fs.__type__ == "ntfs"}
    
    def check_compatible(self) -> None:
        if not len(self.ntfs_filesystems):
            raise UnsupportedPluginError("No NTFS filesystems found")
        
    @arg("--fs", type=int, help="optional filesystem index, zero indexed")
    @arg("--start", type=int, default=0, help="the first MFT segment number")
    @arg("--end", type=int, default=-1, help="the last MFT segment number")
    def records(
        self, fs: int | None = None, start: int = 0, end: int = -1
    ) -> Iterator[
        ZoneIdentifierRecord
    ]:
        """Return the MFT records of all NTFS filesystems.

        The Master File Table (MFT) contains primarily metadata about every file and folder on a NFTS filesystem.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the MFT properties
        added to it through a "fake" ``NtfsFilesystem``), the paths returned in the MFT records are based on the
        mount point of the ``VirtualFilesystem``. This ensures that the proper original drive letter is used when
        available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
        """

        filesystems: list[NtfsFilesystem] = []
        if fs is not None:
            try:
                filesystems = [self.ntfs_filesystems[fs]]
            except KeyError:
                self.target.log.error("NTFS filesystem with index number %s does not exist", fs)  # noqa: TRY400
                return
        else:
            filesystems = self.ntfs_filesystems.values()

        for filesystem in filesystems:
            info = _Info.init(self.target, filesystem)

            try:
                for record in filesystem.ntfs.mft.segments(start, end):
                    try:
                        info.update(record, filesystem)

                        for path in record.full_paths():
                            path = f"{info.drive_letter}{path}"
                            yield from iter_records(
                                record=record,
                                segment=record.segment,
                                path=path,
                                drive_letter=info.drive_letter,
                                volume_uuid=info.volume_uuid,
                                target=self.target,
                            )
                    except Exception as e:  # noqa: PERF203
                        self.target.log.warning("An error occured parsing MFT segment %d: %s", record.segment, str(e))
                        self.target.log.debug("", exc_info=e)

            except Exception:
                self.target.log.exception("An error occured constructing FilesystemRecords")
    __call__ = records

    def iter_records(
        record: MftRecord,
        segment: int,
        path: str,
        drive_letter: str,
        volume_uuid: str,
        target: Target,
    ) -> Iterator[Record]:
        yield None