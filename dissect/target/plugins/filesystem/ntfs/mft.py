import logging

from dissect.ntfs.c_ntfs import FILE_RECORD_SEGMENT_IN_USE
from dissect.ntfs.mft import MftRecord
from flow.record.fieldtypes import uri

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.ntfs.utils import (
    get_drive_letter,
    get_owner_and_group,
    get_record_size,
    get_volume_identifier,
)

log = logging.getLogger(__name__)


FilesystemStdRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/std",
    [
        ("datetime", "creation_time"),
        ("datetime", "last_modification_time"),
        ("datetime", "last_change_time"),
        ("datetime", "last_access_time"),
        ("uint32", "segment"),
        ("uri", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("string", "volume_uuid"),
    ],
)


FilesystemFilenameRecord = TargetRecordDescriptor(
    "filesystem/ntfs/mft/filename",
    [
        ("datetime", "creation_time"),
        ("datetime", "last_modification_time"),
        ("datetime", "last_change_time"),
        ("datetime", "last_access_time"),
        ("uint32", "filename_index"),
        ("uint32", "segment"),
        ("uri", "path"),
        ("string", "owner"),
        ("filesize", "filesize"),
        ("boolean", "resident"),
        ("boolean", "inuse"),
        ("boolean", "ads"),
        ("string", "volume_uuid"),
    ],
)


class MftPlugin(Plugin):
    def check_compatible(self):
        ntfs_filesystems = [fs for fs in self.target.filesystems if fs.__fstype__ == "ntfs"]
        return len(ntfs_filesystems) > 0

    @export(record=[FilesystemStdRecord, FilesystemFilenameRecord])
    def mft(self):
        """Return the MFT records of all NTFS filesystems.

        The Master File Table (MFT) contains primarily metadata about every file and folder on a NFTS filesystem.

        Sources:
            - https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
        """
        for fs in self.target.filesystems:
            if fs.__fstype__ != "ntfs":
                continue

            drive_letter = get_drive_letter(self.target, fs)
            volume_uuid = get_volume_identifier(fs)

            try:
                for record in fs.ntfs.mft.segments():
                    segment = record.segment

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
                            yield from self.mft_records(
                                drive_letter=drive_letter,
                                record=record,
                                segment=segment,
                                path=path,
                                owner=owner,
                                size=size,
                                resident=resident,
                                inuse=inuse,
                                volume_uuid=volume_uuid,
                            )
                    except Exception as e:
                        self.target.log.warning("An error occured parsing MFT segment %d: %s", segment, str(e))
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
    ):
        for attr in record.attributes.STANDARD_INFORMATION:
            yield FilesystemStdRecord(
                creation_time=attr.creation_time,
                last_modification_time=attr.last_modification_time,
                last_change_time=attr.last_change_time,
                last_access_time=attr.last_access_time,
                segment=segment,
                path=uri.from_windows(path),
                owner=owner,
                filesize=size,
                resident=resident,
                inuse=inuse,
                volume_uuid=volume_uuid,
                _target=self.target,
            )

        for idx, attr in enumerate(record.attributes.FILE_NAME):
            filepath = f"{drive_letter}{attr.full_path()}"

            yield FilesystemFilenameRecord(
                creation_time=attr.creation_time,
                last_modification_time=attr.last_modification_time,
                last_change_time=attr.last_change_time,
                last_access_time=attr.last_access_time,
                filename_index=idx,
                segment=segment,
                path=uri.from_windows(filepath),
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

            yield FilesystemFilenameRecord(
                creation_time=ads_info.creation_time,
                last_modification_time=ads_info.last_modification_time,
                last_change_time=ads_info.last_change_time,
                last_access_time=ads_info.last_access_time,
                filename_index=None,
                segment=segment,
                path=uri.from_windows(ads_path),
                owner=owner,
                filesize=size,
                resident=resident,
                inuse=inuse,
                ads=True,
                volume_uuid=volume_uuid,
                _target=self.target,
            )
