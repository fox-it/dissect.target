from __future__ import annotations

import typing
import uuid

from dissect.database.ese import ESE
from dissect.database.ese import Table as EseTable
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.bits.c_bits import c_bits

if typing.TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target

BitsRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/filesystem/bits",
    [
        ("string", "job_type"),
        ("string", "state"),
        ("string", "priority"),
        ("string", "job_id"),
        ("string", "name"),
        ("string", "desc"),
        ("string", "callback_cmd"),
        ("string", "callback_args"),
        ("string", "notify_flag"),
        ("datetime", "ctime"),
        ("datetime", "mtime"),
        ("datetime", "mtime_bis"),
        ("datetime", "last_job_transferred_end"),
        ("string", "file_guid"),
        ("string", "file_dst"),
        ("string", "file_src"),
        ("string", "file_tmp"),
        ("varint", "file_dl_size"),
        ("varint", "file_transfer_size"),
        ("string", "file_drive"),
        ("string", "file_volume"),
        ("path", "source"),
    ],
)

# UUID('7756da36-516f-435a-acac-44a248fff34d')

FILE_LIST_STORAGE_GUID = b"\x36\xda\x56\x77\x6f\x51\x5a\x43\xac\xac\x44\xa2\x48\xff\xf3\x4d"


class BitsPlugin(Plugin):
    """Windows Bits (Background Intelligent Transfer Service) plugin. Support pre Win10 and post Win 10 format"""

    def __init__(self, target: Target):
        super().__init__(target)
        self.qmgr_db_path = next(self.get_paths())

    def _get_paths(self) -> Iterator[Path]:
        qmgr_db_path = self.target.path("sysvol/ProgramData/Microsoft/Network/Downloader/qmgr.db")
        if qmgr_db_path.exists():
            yield qmgr_db_path

    def check_compatible(self) -> None:
        if not self.qmgr_db_path:
            raise UnsupportedPluginError("No prefetch files found")

    def build_files_dict(self, file_table: EseTable) -> dict[str, bytes]:
        files_dict = {}
        for entry in file_table.records():
            files_dict[entry["Id"].lower()] = entry["Blob"]
        return files_dict

    @export(record=[BitsRecord])
    def qmgr(self) -> Iterator[BitsRecord]:
        """Return the content of all prefetch files.
        References:
            - https://github.com/fireeye/BitsParser
            - https://github.com/ANSSI-FR/bits_parser
            - https://cloud.google.com/blog/topics/threat-intelligence/attacker-use-of-windows-background-intelligent-transfer-service/
            - /windows/system32/qmgr.dll
        """
        with self.qmgr_db_path.open("rb") as fh:
            db = ESE(fh)
            table = db.table("Jobs")
            files_dict = self.build_files_dict(db.table("Files"))
            print(files_dict)
            for record in table.records():
                ctime = None
                mtime = None
                mtime_bis = None
                last_job_transferred_end = None
                a = record["Blob"]
                entry = c_bits.BitsJobsHeader(a)
                # Jobs header is followed by a security descriptor section. Section total length depends on header guid,
                # As this is prone to errors, we skip this section.
                # Especially since next section has a known start sequence

                storage_guid_list = a[len(entry) :].split(FILE_LIST_STORAGE_GUID)
                if len(storage_guid_list) > 1:
                    # todo : ad test with range/Versionned files
                    file_guid_list = c_bits.BitsJobsFileGuidList(storage_guid_list[1])
                if len(storage_guid_list) > 2:
                    job_has_error = storage_guid_list[2][:4] != b"\x00\x00\x00\x00"
                    if job_has_error:
                        # to find job has error section
                        pass
                    metadata_section = c_bits.BitsMetadata(storage_guid_list[2][4:])
                    ctime = wintimestamp(metadata_section.ctime)
                    mtime = wintimestamp(metadata_section.mtime)
                    mtime_bis = wintimestamp(metadata_section.mtime_bis)
                    last_job_transferred_end = (
                        wintimestamp(metadata_section.last_job_transferred_end)
                        if metadata_section.last_job_transferred_end != 0
                        else None
                    )

                user_sid = entry.sid.strip("\x00")
                user = None
                if user_sid and (sid_user_details := self.target.user_details.find(user_sid)):
                    user = sid_user_details.user

                for file_entry in file_guid_list.files_guid:
                    file_guid = uuid.UUID(bytes_le=file_entry)
                    if file_blob := files_dict.get(str(file_guid).lower()):
                        f = c_bits.BitsFile(file_blob)
                        yield BitsRecord(
                            job_type=entry.type.name,
                            state=entry.state.name,
                            priority=entry.priority.name,
                            job_id=uuid.UUID(bytes_le=entry.job_id),
                            name=entry.name.strip("\x00"),
                            desc=entry.desc.strip("\x00"),
                            callback_cmd=entry.callback_cmd.strip("\x00"),
                            callback_args=entry.callback_args.strip("\x00"),
                            notify_flag=entry.notify_flag.name,
                            ctime=ctime,
                            mtime=mtime,
                            mtime_bis=mtime_bis,
                            last_job_transferred_end=last_job_transferred_end,
                            file_guid=file_guid,
                            file_drive=f.drive.strip("\x00"),
                            file_dst=f.dst.strip("\x00"),
                            file_src=f.src.strip("\x00"),
                            file_tmp=f.tmp.strip("\x00"),
                            file_volume=f.volume.strip("\x00"),
                            file_dl_size=f.dl_size,
                            file_transfer_size=f.transfer_size,
                            user_id=user_sid,
                            _user=user,
                            _target=self.target,
                            source=self.qmgr_db_path,
                        )
                if not file_guid_list.files_guid:
                    yield BitsRecord(
                        job_type=entry.type.name,
                        state=entry.state.name,
                        priority=entry.priority.name,
                        job_id=uuid.UUID(bytes_le=entry.job_id),
                        name=entry.name.strip("\x00"),
                        desc=entry.desc.strip("\x00"),
                        callback_cmd=entry.callback_cmd.strip("\x00"),
                        callback_args=entry.callback_args.strip("\x00"),
                        notify_flag=entry.notify_flag.name,
                        ctime=ctime,
                        mtime=mtime,
                        mtime_bis=mtime_bis,
                        last_job_transferred_end=last_job_transferred_end,
                        user_id=user_sid,
                        _user=user,
                        _target=self.target,
                        source=self.qmgr_db_path,
                    )
