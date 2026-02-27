from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import UnsupportedPluginError
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
    from dissect.ntfs.attr import Attribute, FileName, StandardInformation
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

ZoneIdentifierRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/zone",
    [
        ("uint32", "zone_id"),
        ("string", "referrer_url"),
        ("string", "host_url"),
        ("uint32", "app_zone_id"),
        ("string", "host_ip_address"),
        ("string", "last_writer"),
        ("path", "file_path"),
        ("string", "volume_uuid"),
        ("uint32", "segment"),
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
    @arg("--fs", type=int, help="optional filesystem index, zero indexed")
    @arg("--start", type=int, default=0, help="the first MFT segment number")
    @arg("--end", type=int, default=-1, help="the last MFT segment number")
    @arg(
        "--macb",
        group="fmt",
        action="store_true",
        help="compacts MFT timestamps into MACB bitfield (format: MACB[standard|ads]/MACB[filename])",
    )
    def records(
        self, compact: bool = False, fs: int | None = None, start: int = 0, end: int = -1, macb: bool = False
    ) -> Iterator[
        FilesystemStdRecord | FilesystemFilenameRecord | FilesystemStdCompactRecord | FilesystemFilenameCompactRecord
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

        record_formatter = default_formatter

        def noop_aggregator(records: Iterator[Record]) -> Iterator[Record]:
            yield from records

        aggregator = noop_aggregator

        if compact:
            record_formatter = compact_formatter
        elif macb:
            aggregator = macb_aggregator

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
                            yield from aggregator(
                                iter_records(
                                    record=record,
                                    segment=record.segment,
                                    path=path,
                                    owner=info.owner,
                                    size=info.size,
                                    resident=info.resident,
                                    inuse=info.in_use,
                                    drive_letter=info.drive_letter,
                                    volume_uuid=info.volume_uuid,
                                    record_formatter=record_formatter,
                                    target=self.target,
                                )
                            )
                    except Exception as e:  # noqa: PERF203
                        self.target.log.warning("An error occured parsing MFT segment %d: %s", record.segment, str(e))
                        self.target.log.debug("", exc_info=e)

            except Exception:
                self.target.log.exception("An error occured constructing FilesystemRecords")

    # Make calling the `mft` namespace backwards compatible with the old `mft` function
    __call__ = records

    @export(output="yield")
    @arg("--ignore-dos", action="store_true", help="ignore DOS file names")
    def timeline(self, ignore_dos: bool = False) -> Iterator[str]:
        """Return the MFT records of all NTFS filesystems in a human readable format (unsorted).

        The Master File Table (MFT) contains metadata about every file and folder on a NFTS filesystem.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the MFT properties
        added to it through a "fake" ``NtfsFilesystem``), the paths returned in the MFT records are based on the
        mount point of the ``VirtualFilesystem``. This ensures that the proper original drive letter is used when
        available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
        """
        for fs in self.target.filesystems:
            if fs.__type__ != "ntfs":
                continue
            fs: NtfsFilesystem

            info = _Info.init(self.target, fs)

            for record in fs.ntfs.mft.segments():
                segment = record.segment

                try:
                    info.update(record, fs)

                    for path in record.full_paths(ignore_dos):
                        path = f"{info.drive_letter}{path}"

                        for attr in record.attributes.STANDARD_INFORMATION:
                            yield from format_timeline_info(
                                segment,
                                path,
                                info,
                                attr,
                                InformationType.STANDARD_INFORMATION,
                            )

                        for idx, attr in enumerate(record.attributes.FILE_NAME):
                            filepath = f"{info.drive_letter}{attr.full_path()}"

                            yield from format_timeline_info(
                                segment,
                                filepath,
                                info,
                                attr,
                                InformationType.FILE_INFORMATION,
                                idx=idx,
                            )

                        ads_extras = replace(info)
                        ads_info = record.attributes.FILE_NAME[0]

                        for attr in record.attributes.DATA:
                            if attr.name != "":  # ADS Data
                                ads_extras.resident = attr.resident
                                ads_extras.size = get_record_size(record, attr.name)

                                adspath = f"{path}:{attr.name}"

                                yield from format_timeline_info(
                                    segment,
                                    adspath,
                                    ads_extras,
                                    ads_info,
                                    InformationType.ALTERNATE_DATA_STREAM,
                                )
                except Exception as e:
                    self.target.log.warning("An error occured parsing MFT segment %d: %s", segment, str(e))
                    self.target.log.debug("", exc_info=e)

    @export(output="yield")
    def body(self) -> Iterator[str]:
        """Return the MFT records of all NTFS filesystems in bodyfile format.

        The file mode is not accurate. This value was only added to indicate
        if a record is a file or directory.

        The Master File Table (MFT) contains metadata about every file and folder on a NFTS filesystem.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the MFT properties
        added to it through a "fake" ``NtfsFilesystem``), the paths returned in the MFT records are based on the
        mount point of the ``VirtualFilesystem``. This ensures that the proper original drive letter is used when
        available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
            - https://wiki.sleuthkit.org/index.php?title=Body_file
        """
        for fs in self.target.filesystems:
            if fs.__type__ != "ntfs":
                continue
            fs: NtfsFilesystem

            info = _Info.init(self.target, fs)

            for record in fs.ntfs.mft.segments():
                # Just to make it clear when something is a file or a dir.
                size = 0
                file_mode = "d/drwxrwxrwx"
                if not record.is_dir():
                    size = get_record_size(record)
                    file_mode = "r/rrwxrwxrwx"

                try:
                    for path in record.full_paths(False):
                        path = f"{info.drive_letter}{path}"

                        for attribute in record.attributes.STANDARD_INFORMATION:
                            yield format_body_info(
                                name=path,
                                inode=record.segment,
                                mode_as_string=file_mode,
                                size=size,
                                atime=int(attribute.last_access_time.timestamp()),
                                mtime=int(attribute.last_modification_time.timestamp()),
                                ctime=int(attribute.last_change_time.timestamp()),
                                crtime=int(attribute.creation_time.timestamp()),
                            )
                except Exception as e:
                    self.target.log.warning(
                        "An error occured parsing the $STANDARD_INFORMATION attribute of MFT segment %d: %s",
                        record.segment,
                        str(e),
                    )

                try:
                    for attribute in record.attributes.FILE_NAME:
                        path = f"{info.drive_letter}{attribute.full_path()} ($FILE_NAME)"  # fls like output
                        yield format_body_info(
                            name=path,
                            inode=record.segment,
                            mode_as_string=file_mode,
                            size=size,
                            atime=int(attribute.last_access_time.timestamp()),
                            mtime=int(attribute.last_modification_time.timestamp()),
                            ctime=int(attribute.last_change_time.timestamp()),
                            crtime=int(attribute.creation_time.timestamp()),
                        )
                except Exception as e:
                    self.target.log.warning(
                        "An error occured parsing the $FILE_NAME attribute of MFT segment %d: %s",
                        record.segment,
                        str(e),
                    )

    @export(record=ZoneIdentifierRecord)
    @arg("--fs", type=int, help="optional filesystem index, zero indexed")
    @arg("--start", type=int, default=0, help="the first MFT segment number")
    @arg("--end", type=int, default=-1, help="the last MFT segment number")
    def zone(self, fs: int | None = None, start: int = 0, end: int = -1) -> Iterator[ZoneIdentifierRecord]:
        """Return Zone.Identifier ADS records from NTFS MFT entries."""
        filesystems: list[NtfsFilesystem]
        if fs is not None:
            try:
                filesystems = [self.ntfs_filesystems[fs]]
            except KeyError:
                self.target.log.error("NTFS filesystem with index number %s does not exist", fs)
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

                            yield from iter_zone_records(
                                record=record,
                                segment=record.segment,
                                path=path,
                                volume_uuid=info.volume_uuid,
                                target=self.target,
                            )

                    except Exception as e:
                        self.target.log.warning(
                            "An error occurred parsing MFT segment %d: %s",
                            record.segment,
                            str(e),
                        )
                        self.target.log.debug("", exc_info=e)

            except Exception:
                self.target.log.exception("An error occurred constructing ZoneIdentifier records")


def iter_records(
    record: MftRecord,
    segment: int,
    path: str,
    owner: str,
    size: int,
    resident: bool,
    inuse: bool,
    drive_letter: str,
    volume_uuid: str,
    record_formatter: Callable,
    target: Target,
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
            _target=target,
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
            _target=target,
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
            _target=target,
        )


def compact_formatter(
    attr: Attribute, record_type: InformationType, **kwargs
) -> Iterator[FilesystemStdCompactRecord | FilesystemFilenameCompactRecord]:
    record_desc = COMPACT_RECORD_TYPES.get(record_type)
    yield record_desc(
        creation_time=attr.creation_time,
        last_modification_time=attr.last_modification_time,
        last_change_time=attr.last_change_time,
        last_access_time=attr.last_access_time,
        **kwargs,
    )


def default_formatter(
    attr: Attribute, record_type: InformationType, **kwargs
) -> Iterator[FilesystemStdRecord | FilesystemFilenameRecord]:
    record_desc = RECORD_TYPES.get(record_type)
    for type, timestamp in [
        ("B", attr.creation_time),
        ("C", attr.last_change_time),
        ("M", attr.last_modification_time),
        ("A", attr.last_access_time),
    ]:
        yield record_desc(ts=timestamp, ts_type=type, **kwargs)


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

    def format(self) -> str:
        return (
            f"InUse:{format_none_value(self.in_use)} "
            f"Resident:{format_none_value(self.resident)} "
            f"Owner:{format_none_value(self.owner)} "
            f"Size:{format_none_value(self.size)} "
            f"VolumeUUID:{format_none_value(self.volume_uuid)}"
        )


def format_timeline_info(
    segment: int,
    path: str,
    info: _Info,
    attr: FileName | StandardInformation,
    attr_type: InformationType,
    idx: str = "",
) -> Iterator[str]:
    start_letter, postfix = FORMAT_INFO.get(attr_type, ("", ""))
    timestamps = {
        "B": attr.creation_time,
        "C": attr.last_change_time,
        "M": attr.last_modification_time,
        "A": attr.last_access_time,
    }

    for ts_type, ts in timestamps.items():
        information_type = f"{start_letter}{idx}{ts_type}"
        base_info = f"{ts} {information_type} {segment} {path}"

        yield f"{base_info} - {info.format()}{postfix}"


def format_body_info(
    md5: str = "0",
    name: str = "0",
    inode: int = 0,
    mode_as_string: str = "0",
    uid: int = 0,
    gid: int = 0,
    size: int = 0,
    atime: int = 0,
    mtime: int = 0,
    ctime: int = 0,
    crtime: int = 0,
) -> str:
    return f"{md5}|{name}|{inode}|{mode_as_string}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}"


def format_none_value(value: Any) -> str | Any:
    """Format the value if it is ``None``."""

    return value if value is not None else "No Data"




def iter_zone_records(
    record: MftRecord,
    segment: int,
    path: str,
    volume_uuid: str,
    target: Target,
) -> Iterator[Record]:
    """
    Yields ZoneIdentifierRecord from a validated, single **'Zone.Identifier' ADS**.
    Parses content, validates 'ZoneId' and 'AppZoneId' as numeric, logging errors on failure.

    Args:
        record: The MFT record containing the attributes.
        segment: The MFT segment number.
        path: The file path.
        volume_uuid: The volume UUID.
        target: The target object for logging.

    Yields:
        A ZoneIdentifierRecord object.

    Raises:
        ValueError: Raised by internal calls to `validate_ads_streams` (if >1 stream) or 
                    `parse_zone_identifier_content` (if content is malformed), though 
                    this function catches and handles the exception by logging an error.
    """
    try:
        zone_identifier = validate_ads_streams(target, record, path)
        if not zone_identifier:
            return
        zone_identifier_values = parse_zone_identifier_content(target, zone_identifier, path)
    except ValueError:
        target.log.exception("Error processing Zone.Identifier for Path:%s", path)
        return
    if not zone_identifier_values:
        return
    zone_id = zone_identifier_values.get("ZoneId")
    app_zone_id = zone_identifier_values.get("AppZoneId")
    if zone_id is not None and not zone_id.isdigit():
        target.log.error("ZoneId is not int or None in path: %s", path)
        return
    if app_zone_id is not None and not app_zone_id.isdigit():
        target.log.error("AppZoneId is not int or None in path: %s", path)
        return
    if zone_id is not None:
        zone_id = int(zone_id)
    if app_zone_id is not None:
        app_zone_id = int(app_zone_id)

    yield ZoneIdentifierRecord(
        zone_id=zone_id,
        referrer_url=zone_identifier_values.get("ReferrerUrl"),
        host_url=zone_identifier_values.get("HostUrl"),
        app_zone_id=app_zone_id,
        host_ip_address=zone_identifier_values.get("HostIpAddress"),
        last_writer=zone_identifier_values.get("LastWriterPackageFamilyName"),
        file_path=path,
        volume_uuid=volume_uuid,
        segment=segment,
    )


def validate_ads_streams(target: Target, record: MftRecord, path: str) -> Attribute | None:
    """
    Returns the single 'Zone.Identifier' ADS attribute if exactly one is present.

    Args:
        target: The Target object used for logging.
        record: The MFT record containing the attributes.
        path: The file path (used only for the error message).

    Returns:
        The single 'Zone.Identifier' attribute object if found, otherwise None.
    """
    zone_streams = [attr for attr in record.attributes.DATA if attr.name == "Zone.Identifier"]
    count = len(zone_streams)
    if count > 1:
        # Policy violation: Only one Zone.Identifier stream is allowed.
        target.log.error("more theen 1 zone identifier ADS for file %s", path)
        return None

    if count == 1:
        return zone_streams[0]
    
    return None




def parse_zone_identifier_content(target: Target, attr: Attribute, path: str) -> dict | None:
    """
    Reads, decodes, and parses the INI content from the Zone.Identifier ADS attribute.

    It validates the content starts with the '[ZoneTransfer]' header and validates
    the structure against basic INI formatting (key=value on each line).

    Args:
        target: The Target object used for logging unrecognized keys.
        attr: The Attribute object containing the raw data of the ADS stream.
        path: The file path (used only for the error messages).


    Returns:
        A dictionary containing the parsed key-value pairs from the
        [ZoneTransfer] section of the Zone.Identifier content or None if there was an issue.
    """

    EXPECTED_KEYS = {"AppZoneId", "HostIpAddress", "HostUrl", "LastWriterPackageFamilyName", "ReferrerUrl", "ZoneId"}

    content = attr.data()
    # verify the header and split into lines
    if not content.startswith(b"[ZoneTransfer]\r\n"):
        target.log.error("Missing [ZoneTransfer] header for file %s", path)
        return None
    lines = content.split(b"\r\n")
    # remove the header line
    lines = lines[1:]

    # Check for excessive lines of data
    if len(lines) > len(EXPECTED_KEYS):
        target.log.error("Too many data lines for file %s", path)
        return None

    # Simple, non-robust built-in parsing for Zone.Identifier format
    config_data = {}

    for line in lines:
        try:
            utf_line = line.decode("utf-8")
        except UnicodeDecodeError as exc:
                target.log.error("Cannot decode attribute data for file %s", path)
                return None
        if not utf_line.strip():  # Skip empty or whitespace-only lines
            continue
        if "=" not in utf_line:
            target.log.error("Malformed key-value line for file %s", path)
            return None
        # split limited to one as URL can have = sign
        key, value = utf_line.split("=", 1)
        if key not in EXPECTED_KEYS:
            target.log.error("Unrecognized Key in ZoneIdentifier: %s for file %s", key, path)
            continue

        config_data[key] = value
    return config_data

