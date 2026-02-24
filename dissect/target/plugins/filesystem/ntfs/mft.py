from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dissect.ntfs.attr import FileName
from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.hashutil import md5 as md5_hash
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.ntfs.utils import (
    InformationType,
    get_drive_letter,
    get_owner_and_group,
    get_record_size,
    get_volume_identifier,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dissect.ntfs import MftRecord
    from dissect.ntfs.attr import StandardInformation
    from flow.record import Record
    from typing_extensions import Self

    from dissect.target.filesystems.ntfs import NtfsFilesystem
    from dissect.target.target import Target


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
    InformationType.ALTERNATE_DATA_STREAM: FilesystemFilenameRecord,
}


COMPACT_RECORD_TYPES = {
    InformationType.STANDARD_INFORMATION: FilesystemStdCompactRecord,
    InformationType.FILE_INFORMATION: FilesystemFilenameCompactRecord,
    InformationType.ALTERNATE_DATA_STREAM: FilesystemFilenameCompactRecord,
}

FORMAT_INFO = {
    InformationType.FILE_INFORMATION: ("F", ""),
    InformationType.STANDARD_INFORMATION: ("S", ""),
    InformationType.ALTERNATE_DATA_STREAM: ("F", " Is_ADS"),
}


class MftPlugin(Plugin):
    """NTFS MFT plugin."""

    __namespace__ = "mft"

    def __init__(self, target: Target):
        super().__init__(target)
        self.ntfs_filesystems = {index: fs for index, fs in enumerate(self.target.filesystems) if fs.__type__ == "ntfs"}

    def check_compatible(self) -> None:
        if not len(self.ntfs_filesystems):
            raise UnsupportedPluginError("No NTFS filesystems found")

    def __iterate_ntfs_filesystems(
        self,
        aggregator: Callable[[Iterator[Record]], Iterator[Record]],
        formatter: Callable[[FileName | StandardInformation, InformationType], Iterator[Any]],
        ignore_dos: bool,
        fs: int | None = None,
        start: int = 0,
        end: int = -1,
    ) -> Iterator[Any]:
        """The Master File Table (MFT) contains primarily metadata about every file and folder on a NFTS filesystem.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the MFT properties
        added to it through a "fake" ``NtfsFilesystem``), the paths returned in the MFT records are based on the
        mount point of the ``VirtualFilesystem``. This ensures that the proper original drive letter is used when
        available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        Args:
            aggregator (Callable[[Iterator[Record]], Iterator[Record]]): Aggregator function
            formatter (Callable[[FileName | StandardInformation, InformationType], Iterator[Any]]): Formatter function
            ignore_dos (bool): Should ignore dos file names
            fs (int | None, optional): fs index to ran on. Defaults to None.
            start (int, optional): start segment. Defaults to 0.
            end (int, optional): end segment. Defaults to -1.

        Yields:
            Iterator[Any]: Yields according to the formatter used (str, records etc).

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

                        yield from aggregator(
                            iter_records(
                                record=record,
                                ignore_dos=ignore_dos,
                                info=info,
                                formatter=formatter,
                                target=self.target,
                            )
                        )
                    except Exception as e:  # noqa: PERF203
                        self.target.log.warning("An error occured parsing MFT segment %d: %s", record.segment, str(e))
                        self.target.log.debug("", exc_info=e)

            except Exception:
                self.target.log.exception("An error occured constructing FilesystemRecords")

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
    @arg(
        "--macb",
        group="fmt",
        action="store_true",
        help="compacts MFT timestamps into MACB bitfield (format: MACB[standard|ads]/MACB[filename])",
    )
    @arg("--ignore-dos", action="store_true", help="ignore DOS file names")
    @arg("--fs", type=int, help="optional filesystem index, zero indexed")
    @arg("--start", type=int, default=0, help="the first MFT segment number")
    @arg("--end", type=int, default=-1, help="the last MFT segment number")
    def records(
        self,
        compact: bool = False,
        macb: bool = False,
        ignore_dos: bool = False,
        fs: int | None = None,
        start: int = 0,
        end: int = -1,
    ) -> Iterator[
        FilesystemStdRecord | FilesystemFilenameRecord | FilesystemStdCompactRecord | FilesystemFilenameCompactRecord
    ]:
        """Return the MFT records of all NTFS filesystems.

        Args:
            compact (bool, optional): Should compact timestamps to one record. Defaults to False.
            macb (bool, optional): Should generate records using macb. Defaults to False.
            ignore_dos (bool): Should ignore dos file names
            fs (int | None, optional): fs index to ran on. Defaults to None.
            start (int, optional): start segment. Defaults to 0.
            end (int, optional): end segment. Defaults to -1.

        Yields:
            Iterator[Record]: Yields all MFT records
        """
        record_formatter = default_formatter
        aggregator = noop_aggregator

        if compact:
            record_formatter = compact_formatter
        elif macb:
            aggregator = macb_aggregator

        yield from self.__iterate_ntfs_filesystems(aggregator, record_formatter, ignore_dos, fs, start, end)

    @export(output="yield")
    @arg("--ignore-dos", action="store_true", help="ignore DOS file names")
    def timeline(self, ignore_dos: bool = False) -> Iterator[str]:
        """Return the MFT records of all NTFS filesystems in a human readable format (unsorted).

        Args:
            ignore_dos (bool): Should ignore dos file names

        Yields:
            Iterator[Record]: Yields timeline info as string
        """
        yield from self.__iterate_ntfs_filesystems(noop_aggregator, format_timeline_info, ignore_dos=ignore_dos)

    @export(output="yield")
    def body(self) -> Iterator[str]:
        """Return the MFT records of all NTFS filesystems in bodyfile format.

        The file mode is not accurate. This value was only added to indicate
        if a record is a file or directory.

        Yields:
            Iterator[Record]: Yields NTFS bodyfile as string

        References:
            - https://wiki.sleuthkit.org/index.php?title=Body_file
        """
        yield from self.__iterate_ntfs_filesystems(noop_aggregator, format_body_info, ignore_dos=False)


def iter_records(
    record: MftRecord,
    ignore_dos: bool,
    info: _Info,
    formatter: Callable,
    target: Target,
) -> Iterator[Record]:
    path = f"{info.drive_letter}{record.full_path(True)}"

    for attr in record.attributes.STANDARD_INFORMATION:
        yield from formatter(
            attr=attr,
            attr_type=InformationType.STANDARD_INFORMATION,
            segment=record.segment,
            path=windows_path(path),
            owner=info.owner,
            filesize=info.size,
            resident=info.resident,
            inuse=info.in_use,
            volume_uuid=info.volume_uuid,
            _target=target,
        )

    for idx, filename_path in enumerate(record.full_paths(ignore_dos)):
        attr = record.attributes.FILE_NAME[idx]
        filepath = f"{info.drive_letter}{filename_path}"

        yield from formatter(
            attr=attr,
            attr_type=InformationType.FILE_INFORMATION,
            filename_index=idx,
            segment=record.segment,
            path=windows_path(filepath),
            owner=info.owner,
            filesize=info.size,
            resident=info.resident,
            ads=False,
            inuse=info.in_use,
            volume_uuid=info.volume_uuid,
            _target=target,
        )

    ads_attributes = (data_attr for data_attr in record.attributes.DATA if data_attr.name != "")
    if record.attributes.STANDARD_INFORMATION:
        ads_info = record.attributes.STANDARD_INFORMATION[0]
    else:
        ads_info = record.attributes.FILE_NAME[0]

    for data_attr in ads_attributes:
        size = get_record_size(record, data_attr.name)
        ads_path = f"{path}:{data_attr.name}"

        yield from formatter(
            attr=ads_info,
            attr_type=InformationType.ALTERNATE_DATA_STREAM,
            filename_index=None,
            segment=record.segment,
            path=windows_path(ads_path),
            owner=info.owner,
            filesize=size,
            resident=data_attr.resident,
            inuse=info.in_use,
            ads=True,
            volume_uuid=info.volume_uuid,
            _target=target,
        )


def compact_formatter(
    attr: FileName | StandardInformation, attr_type: InformationType, **kwargs
) -> Iterator[FilesystemStdCompactRecord | FilesystemFilenameCompactRecord]:
    record_desc = COMPACT_RECORD_TYPES.get(attr_type)
    yield record_desc(
        creation_time=attr.creation_time,
        last_modification_time=attr.last_modification_time,
        last_change_time=attr.last_change_time,
        last_access_time=attr.last_access_time,
        **kwargs,
    )


def default_formatter(
    attr: FileName | StandardInformation, attr_type: InformationType, **kwargs
) -> Iterator[FilesystemStdRecord | FilesystemFilenameRecord]:
    record_desc = RECORD_TYPES.get(attr_type)
    for type, timestamp in [
        ("B", attr.creation_time),
        ("C", attr.last_change_time),
        ("M", attr.last_modification_time),
        ("A", attr.last_access_time),
    ]:
        yield record_desc(ts=timestamp, ts_type=type, **kwargs)


def format_none_value(value: Any) -> str | Any:
    """Format the value if it is ``None``."""

    return value if value is not None else "No Data"


def format_timeline_info(
    attr: FileName | StandardInformation,
    attr_type: InformationType,
    path: windows_path,
    segment: int,
    filesize: int,
    inuse: bool,
    resident: bool,
    owner: str | None,
    volume_uuid: str | None,
    filename_index: str | None = None,
    **kwargs,
) -> Iterator[str]:
    start_letter, postfix = FORMAT_INFO.get(attr_type, ("", ""))
    timestamps = {
        "B": attr.creation_time,
        "C": attr.last_change_time,
        "M": attr.last_modification_time,
        "A": attr.last_access_time,
    }

    if filename_index is None:
        filename_index = ""

    info = (
        f"InUse:{format_none_value(inuse)} "
        f"Resident:{format_none_value(resident)} "
        f"Owner:{format_none_value(owner)} "
        f"Size:{format_none_value(filesize)} "
        f"VolumeUUID:{format_none_value(volume_uuid)}"
    )

    for ts_type, ts in timestamps.items():
        information_type = f"{start_letter}{filename_index}{ts_type}"
        base_info = f"{ts} {information_type} {segment} {path}"

        yield f"{base_info} - {info}{postfix}"


def format_body_info(
    attr: FileName | StandardInformation,
    path: windows_path,
    segment: int,
    filesize: int,
    **kwargs,
) -> str:
    # Just to make it clear when something is a file or a dir.
    file_mode = "d/drwxrwxrwx"
    if not attr.is_dir():
        file_mode = "r/rrwxrwxrwx"

    if isinstance(attr, FileName):
        path = f"{path} ($FILE_NAME)"  # fls like output

    md5 = md5_hash(attr.record.open(path.name))

    return (
        f"{md5}|{path}|{segment}|{file_mode}|{attr.owner_id}|{attr.security_id}|"
        f"{filesize}|{attr.last_access_time}|{attr.last_modification_time}|"
        f"{attr.last_change_time}|{attr.creation_time}"
    )


def noop_aggregator(records: Iterator[Record]) -> Iterator[Record]:
    yield from records


def macb_aggregator(records: Iterator[Record]) -> Iterator[Record]:
    def macb_set(bitfield: str, index: int, letter: str) -> str:
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


@dataclass
class _Info:
    in_use: bool | None = None
    resident: bool | None = None
    owner: str | None = None
    size: int | None = None
    serial: int | None = None
    volume_uuid: str | None = None
    drive_letter: str | None = None

    @classmethod
    def init(cls, target: Target, fs: NtfsFilesystem) -> Self:
        # If this filesystem is a "fake" NTFS filesystem, used to enhance a
        # VirtualFilesystem, The driveletter (more accurate mount point)
        # returned will be that of the VirtualFilesystem. This makes sure
        # the paths returned in the records are actually reachable.
        return cls(
            serial=fs.ntfs.serial,
            volume_uuid=get_volume_identifier(fs),
            drive_letter=get_drive_letter(target, fs),
        )

    def update(self, record: MftRecord, fs: NtfsFilesystem) -> None:
        in_use = bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE)
        owner, _ = get_owner_and_group(record, fs)
        resident = None
        size = None

        if not record.is_dir():
            for data_attribute in record.attributes.DATA:
                if data_attribute.name == "":
                    resident = data_attribute.resident
                    break

            size = get_record_size(record)

        self.in_use = in_use
        self.resident = resident
        self.size = size
        self.owner = owner
