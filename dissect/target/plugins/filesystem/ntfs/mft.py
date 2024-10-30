from __future__ import annotations

import logging
from typing import Callable, Iterator

from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import MftRecord
from flow.record import Record
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.ntfs.utils import (
    InformationType,
    get_drive_letter,
    get_owner_and_group,
    get_record_size,
    get_volume_identifier,
)

log = logging.getLogger(__name__)


FilesystemStdCompactRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/std/compact",
    [
        ("datetime", "creation_time"),
        ("datetime", "last_modification_time"),
        ("datetime", "last_change_time"),
        ("datetime", "last_access_time"),
        ("uint32", "segment"),
        ("path", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("string", "volume_uuid"),
    ],
)


FilesystemStdRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/std",
    [
        ("datetime", "ts"),
        ("string", "ts_type"),
        ("uint32", "segment"),
        ("path", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("string", "volume_uuid"),
    ],
)

FilesystemFilenameCompactRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/filename/compact",
    [
        ("datetime", "creation_time"),
        ("datetime", "last_modification_time"),
        ("datetime", "last_change_time"),
        ("datetime", "last_access_time"),
        ("uint32", "filename_index"),
        ("uint32", "segment"),
        ("path", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("boolean", "ads"),
        ("string", "volume_uuid"),
    ],
)

FilesystemFilenameRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/filename",
    [
        ("datetime", "ts"),
        ("string", "ts_type"),
        ("uint32", "filename_index"),
        ("uint32", "segment"),
        ("path", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("boolean", "ads"),
        ("string", "volume_uuid"),
    ],
)

FilesystemMACBRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/macb",
    [
        ("datetime", "ts"),
        ("string", "macb"),
        ("uint32", "filename_index"),
        ("uint32", "segment"),
        ("path", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("boolean", "ads"),
        ("string", "volume_uuid"),
    ],
)

RECORD_TYPES = {
    InformationType.STANDARD_INFORMATION: FilesystemStdRecord,
    InformationType.FILE_INFORMATION: FilesystemFilenameRecord,
}


COMPACT_RECORD_TYPES = {
    InformationType.STANDARD_INFORMATION: FilesystemStdCompactRecord,
    InformationType.FILE_INFORMATION: FilesystemFilenameCompactRecord,
}


class MftPlugin(Plugin):
    """NTFS MFT plugin."""

    def __init__(self, target):
        super().__init__(target)
        self.ntfs_filesystems = {index: fs for index, fs in enumerate(self.target.filesystems) if fs.__type__ == "ntfs"}

    def check_compatible(self) -> None:
        if not len(self.ntfs_filesystems):
            raise UnsupportedPluginError("No NTFS filesystems found")

    @export(
        record=[
            FilesystemStdRecord,
            FilesystemFilenameRecord,
            FilesystemStdCompactRecord,
            FilesystemFilenameCompactRecord,
        ]
    )
    @arg(
        "--compact",
        group="fmt",
        action="store_true",
        help="compacts the MFT entry timestamps into a single record",
    )
    @arg("--fs", type=int, default=None, help="optional filesystem index, zero indexed")
    @arg("--start", type=int, default=0, help="the first MFT segment number")
    @arg("--end", type=int, default=-1, help="the last MFT segment number")
    @arg(
        "--macb",
        group="fmt",
        action="store_true",
        help="compacts MFT timestamps into MACB bitfield (format: MACB[standard|ads]/MACB[filename])",
    )
    def mft(
        self, compact: bool = False, fs: int | None = None, start: int = 0, end: int = -1, macb: bool = False
    ) -> Iterator[Record]:
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

        record_formatter = formatter

        def noaggr(records: list[Record]) -> Iterator[Record]:
            yield from records

        aggr = noaggr

        if compact:
            record_formatter = compacted_formatter
        elif macb:
            aggr = macb_aggr

        if fs is not None:
            try:
                filesystem = self.ntfs_filesystems[fs]
            except KeyError:
                self.target.log.error("NTFS filesystem with index number %s does not exist", fs)
                return

            yield from self.segments(filesystem, record_formatter, aggr, start, end)
        else:
            for filesystem in self.ntfs_filesystems.values():
                yield from self.segments(filesystem, record_formatter, aggr, start, end)

    def segments(
        self, fs: NtfsFilesystem, record_formatter: Callable, aggr: Callable, start: int, end: int
    ) -> Iterator[Record]:
        # If this filesystem is a "fake" NTFS filesystem, used to enhance a
        # VirtualFilesystem, The driveletter (more accurate mount point)
        # returned will be that of the VirtualFilesystem. This makes sure
        # the paths returned in the records are actually reachable.
        drive_letter = get_drive_letter(self.target, fs)
        volume_uuid = get_volume_identifier(fs)

        try:
            for record in fs.ntfs.mft.segments(start, end):
                try:
                    inuse = bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE)
                    owner, _ = get_owner_and_group(record, fs)
                    resident = None
                    size = None

                    if not record.is_dir():
                        for data_attribute in record.attributes.DATA:
                            if data_attribute.name == "":
                                resident = data_attribute.resident
                                break

                        size = get_record_size(record)

                    for path in record.full_paths():
                        path = f"{drive_letter}{path}"
                        yield from aggr(
                            self.mft_records(
                                drive_letter=drive_letter,
                                record=record,
                                segment=record.segment,
                                path=path,
                                owner=owner,
                                size=size,
                                resident=resident,
                                inuse=inuse,
                                volume_uuid=volume_uuid,
                                record_formatter=record_formatter,
                            )
                        )
                except Exception as e:
                    self.target.log.warning("An error occured parsing MFT segment %d: %s", record.segment, str(e))
                    self.target.log.debug("", exc_info=e)

        except Exception:
            log.exception("An error occured constructing FilesystemRecords")

    def mft_records(
        self,
        drive_letter: str,
        record: MftRecord,
        segment: int,
        path: str,
        owner: str,
        size: int,
        resident: bool,
        inuse: bool,
        volume_uuid: str,
        record_formatter: Callable,
    ) -> Iterator[Record]:
        for attr in record.attributes.STANDARD_INFORMATION:
            yield from record_formatter(
                attr=attr,
                record_type=InformationType.STANDARD_INFORMATION,
                segment=segment,
                path=windows_path(path),
                owner=owner,
                filesize=size,
                resident=resident,
                inuse=inuse,
                volume_uuid=volume_uuid,
                _target=self.target,
            )

        for idx, attr in enumerate(record.attributes.FILE_NAME):
            filepath = f"{drive_letter}{attr.full_path()}"

            yield from record_formatter(
                attr=attr,
                record_type=InformationType.FILE_INFORMATION,
                filename_index=idx,
                segment=segment,
                path=windows_path(filepath),
                owner=owner,
                filesize=size,
                resident=resident,
                ads=False,
                inuse=inuse,
                volume_uuid=volume_uuid,
                _target=self.target,
            )

        ads_attributes = (data_attr for data_attr in record.attributes.DATA if data_attr.name != "")
        ads_info = record.attributes.FILE_NAME[0]

        for data_attr in ads_attributes:
            resident = data_attr.resident
            size = get_record_size(record, data_attr.name)
            ads_path = f"{path}:{data_attr.name}"

            yield from record_formatter(
                attr=ads_info,
                record_type=InformationType.FILE_INFORMATION,
                filename_index=None,
                segment=segment,
                path=windows_path(ads_path),
                owner=owner,
                filesize=size,
                resident=resident,
                inuse=inuse,
                ads=True,
                volume_uuid=volume_uuid,
                _target=self.target,
            )


def compacted_formatter(attr: Attribute, record_type: InformationType, **kwargs) -> Iterator[Record]:
    record_desc = COMPACT_RECORD_TYPES.get(record_type)
    yield record_desc(
        creation_time=attr.creation_time,
        last_modification_time=attr.last_modification_time,
        last_change_time=attr.last_change_time,
        last_access_time=attr.last_access_time,
        **kwargs,
    )


def formatter(attr: Attribute, record_type: InformationType, **kwargs) -> Iterator[Record]:
    record_desc = RECORD_TYPES.get(record_type)
    for type, timestamp in [
        ("B", attr.creation_time),
        ("C", attr.last_change_time),
        ("M", attr.last_modification_time),
        ("A", attr.last_access_time),
    ]:
        yield record_desc(ts=timestamp, ts_type=type, **kwargs)


def macb_aggr(records: list[Record]) -> Iterator[Record]:
    def macb_set(bitfield, index, letter):
        return bitfield[:index] + letter + bitfield[index + 1 :]

    macbs = []
    for record in records:
        found = False

        offset = 0
        if not getattr(record, "ads", False):
            offset = int(record._desc.name == "filesystem/ntfs/mft/filename") * 5

        field = "MACB".find(record.ts_type) + offset
        for macb in macbs:
            if macb.ts == record.ts and macb.path == record.path:
                macb.macb = macb_set(macb.macb, field, record.ts_type)
                found = True
                break

        if found:
            continue

        macb = FilesystemMACBRecord.init_from_record(record)
        macb.macb = "..../...."
        macb.macb = macb_set(macb.macb, field, record.ts_type)

        macbs.append(macb)

    yield from macbs
