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
        ("uint32", "app_zone_id"),
        ("string", "host_ip_address"),
        ("string", "last_writer_package_family_name"),
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
    try:
        zone_identifier = validate_ads_streams(record)
        zone_identifier_values = parse_zone_identifier_content(zone_identifier, target)
    except ValueError as error:
        target.log.error("%s for Path:%s", error, path)
    yield ZoneIdentifierRecord()


def validate_ads_streams(record: MftRecord) -> Attribute | None:
    """
    Returns the single 'Zone.Identifier' ADS attribute if exactly one is present.

    Args:
        record: The MFT record containing the attributes.
        path: The file path (used only for the exception message).

    Returns:
        The single 'Zone.Identifier' attribute object if found, otherwise None.
        
    Raises:
        ValueError: If more than one 'Zone.Identifier' ADS is present.
    """
    zone_streams = [
        attr for attr in record.attributes.DATA 
        if attr.name == "Zone.Identifier"
    ]
    
    count = len(zone_streams)
    print(count)
    if count > 1:
        # Policy violation: Only one Zone.Identifier stream is allowed.
        raise ValueError("more then 1 zone id")
        
    if count == 1:
        return zone_streams[0]

    # Implicitly skips (yields nothing) if count is 0.


def parse_zone_identifier_content(
    attr: Attribute,
    target: Target
) -> dict:
    """
    Reads, decodes, and parses the INI content from the Zone.Identifier ADS attribute.

    It validates the content starts with the '[ZoneTransfer]' header and validates 
    the structure against basic INI formatting (key=value on each line).

    Args:
        attr: The Attribute object containing the raw data of the ADS stream.
        target: The Target object used for logging unrecognized keys.

    Returns:
        A dictionary containing the parsed key-value pairs from the 
        [ZoneTransfer] section of the Zone.Identifier content.

    Raises:
        ValueError: If decoding fails, the content is missing the expected 
                    '[ZoneTransfer]' header, a line is malformed (missing '='), 
                    or the content has too many lines of data.
    """

    EXPECTED_KEYS = {
        "AppZoneId",
        "HostIpAddress",
        "HostUrl",
        "LastWriterPackageFamilyName",
        "ReferrerUrl",
        "ZoneId"
    }

    # Read and Decode the ADS content
    try:
        content = attr.data().decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise ValueError("Cannot decode attribute data") from exc
    
    if not content.startswith("[ZoneTransfer]\r\n"):
        raise ValueError("Missing [ZoneTransfer] header")
    
    lines = content.split('\r\n')
    lines = lines[1:]
    
    # Check for excessive lines of data
    if len(lines) > len(EXPECTED_KEYS):
        raise ValueError("Too many data lines")

    # Simple, non-robust built-in parsing for Zone.Identifier format
    config_data = {}
    
    # Re-split content using splitlines() for the line-by-line parsing logic
    lines = content.splitlines() 
    
    for line in lines:
        if not line.strip():  # Skip empty or whitespace-only lines
            continue
        
        if '=' not in line:
            raise ValueError("Malformed key-value line")
        
        key, value = line.split('=', 1)
        
        if key not in EXPECTED_KEYS:
            target.log.error("Unrecognized Key in ZoneIdentifier: ", key)
            continue
        
        config_data[key] = value
        
    return config_data