from enum import Enum, auto
from dataclasses import dataclass, replace
from typing import Any, Iterator, Optional, Union

from dissect.ntfs.attr import FileName, StandardInformation
from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import MftRecord

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.filesystem.ntfs.utils import (
    get_drive_letter,
    get_owner_and_group,
    get_record_size,
    get_volume_identifier,
)


class InformationType(Enum):
    STANDARD_INFORMATION = auto()
    FILE_INFORMATION = auto()
    ALTERNATE_DATA_STREAM = auto()


def format_none_value(value: Any) -> Union[str, Any]:
    """Format the value if it is None"""

    return value if value is not None else "No Data"


@dataclass
class Extras:
    in_use: Optional[bool] = None
    resident: Optional[bool] = None
    owner: Optional[str] = None
    size: Optional[int] = None
    serial: Optional[int] = None
    volume_uuid: Optional[str] = None

    def format(self) -> str:
        return (
            f"InUse:{format_none_value(self.in_use)} "
            f"Resident:{format_none_value(self.resident)} "
            f"Owner:{format_none_value(self.owner)} "
            f"Size:{format_none_value(self.size)} "
            f"VolumeUUID:{format_none_value(self.volume_uuid)}"
        )


FORMAT_INFO = {
    InformationType.FILE_INFORMATION: ("F", ""),
    InformationType.STANDARD_INFORMATION: ("S", ""),
    InformationType.ALTERNATE_DATA_STREAM: ("F", " Is_ADS"),
}


def _update_extras(extras: Extras, record: MftRecord, fs: NtfsFilesystem) -> None:
    in_use = bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE)
    resident = None
    size = None
    owner, _ = get_owner_and_group(record, fs)

    if not record.is_dir():
        for data_attribute in record.attributes.DATA:
            if data_attribute.name == "":
                resident = data_attribute.resident
                break

        size = get_record_size(record)

    extras.in_use = in_use
    extras.resident = resident
    extras.size = size
    extras.owner = owner


def format_info(
    segment: int,
    path: str,
    extras: Extras,
    info: Union[FileName, StandardInformation],
    info_type: InformationType,
    idx: str = "",
) -> Iterator[str]:
    start_letter, postfix = FORMAT_INFO.get(info_type, ("", ""))
    timestamps = {
        "B": info.creation_time,
        "C": info.last_change_time,
        "M": info.last_modification_time,
        "A": info.last_access_time,
    }

    for ts_type, ts in timestamps.items():
        information_type = f"{start_letter}{idx}{ts_type}"
        base_info = f"{ts} {information_type} {segment} {path}"

        yield f"{base_info} - {extras.format()}{postfix}"


class MftTimelinePlugin(Plugin):
    def check_compatible(self):
        ntfs_filesystems = [fs for fs in self.target.filesystems if fs.__fstype__ == "ntfs"]
        return len(ntfs_filesystems) > 0

    @export(output="yield")
    @arg("--ignore-dos", action="store_true", help="ignore DOS file names")
    def mft_timeline(self, ignore_dos: bool = False):
        """Return the MFT records of all NTFS filesystems in a human readable format (unsorted).

        The Master File Table (MFT) contains metadata about every file and folder on a NFTS filesystem.

        Sources:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
        """
        for fs in self.target.filesystems:
            if fs.__fstype__ != "ntfs":
                continue

            drive_letter = get_drive_letter(self.target, fs)
            extras = Extras(
                serial=fs.ntfs.serial,
                volume_uuid=get_volume_identifier(fs),
            )

            for record in fs.ntfs.mft.segments():
                segment = record.segment
                paths = record.full_paths(ignore_dos)

                _update_extras(extras, record, fs)

                for path in paths:
                    path = f"{drive_letter}{path}"

                    for attr in record.attributes.STANDARD_INFORMATION:
                        yield from format_info(
                            segment,
                            path,
                            extras,
                            attr,
                            InformationType.STANDARD_INFORMATION,
                        )

                    for idx, attr in enumerate(record.attributes.FILE_NAME):
                        filepath = f"{drive_letter}{attr.full_path()}"

                        yield from format_info(
                            segment,
                            filepath,
                            extras,
                            attr,
                            InformationType.FILE_INFORMATION,
                            idx=idx,
                        )

                    ads_extras = replace(extras)
                    ads_info = record.attributes.FILE_NAME[0]

                    for attr in record.attributes.DATA:
                        if attr.name != "":  # ADS Data
                            ads_extras.resident = attr.resident
                            ads_extras.size = get_record_size(record, attr.name)

                            adspath = f"{path}:{attr.name}"

                            yield from format_info(
                                segment,
                                adspath,
                                ads_extras,
                                ads_info,
                                InformationType.ALTERNATE_DATA_STREAM,
                            )
