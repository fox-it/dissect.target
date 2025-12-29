from __future__ import annotations

import struct
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
        ("boolean", "has_error"),
        ("datetime", "job_ctime"),  # Uploaded file mtime
        ("datetime", "job_mtime"),
        ("datetime", "job_mtime_bis"),
        ("datetime", "job_completion_time"),  # Transfer completion time
        ("datetime", "transferred_file_mtime"),  # mtime of file from source for download, or from fs for uploads
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
    """Windows Bits (Background Intelligent Transfer Service) plugin. Only support post Win 10 format"""

    def __init__(self, target: Target):
        super().__init__(target)
        self.qmgr_db_paths = self.get_paths()

    def _get_paths(self) -> Iterator[Path]:
        qmgr_db_path = self.target.fs.path("sysvol/ProgramData/Microsoft/Network/Downloader/qmgr.db")
        if qmgr_db_path.exists():
            yield qmgr_db_path

    def check_compatible(self) -> None:
        if not self.qmgr_db_paths:
            raise UnsupportedPluginError("No qmgr ESE database found")

    def build_files_dict(self, file_table: EseTable) -> dict[str, bytes]:
        files_dict = {}
        for entry in file_table.records():
            files_dict[entry["Id"].lower()] = entry["Blob"]
        return files_dict

    def get_job_error_len(self, blob: bytes) -> int:
        """
        Get length of a structure containing information related to error.

        Basic structure pattern

        struct JobError{
            u32 has_error;
            if (has_error != 0x00) {
                u32 unk1;
                s32 unk2;
                u32 unk3;
                u32 unk4;
                u32 unk5;
                u8 has_persistent_state;
                if (has_persistent_state != 0x00) {
                    u32 persistent_state_len;
                    u16 persistent_state[flag];
                }
            }
        };

        :param blob:
        :return:
        """
        if blob[4 * 5 : 4 * 5 + 1] == b"\x00":
            return 21
        return 21 + struct.unpack("<L", blob[4 * 5 + 2 : 4 * 5 + 6])[0] + 2

    @export(record=[BitsRecord])
    def qmgr_ese(self) -> Iterator[BitsRecord]:
        """Return entries found in the qmgr.db file (background intelligent transfer service). Only works for win10+

        Version pre windows 10 use a different format

        References:
            - https://github.com/fireeye/BitsParser
            - https://github.com/ANSSI-FR/bits_parser
            - https://cloud.google.com/blog/topics/threat-intelligence/attacker-use-of-windows-background-intelligent-transfer-service/
            - /windows/system32/qmgr.dll
        """
        for db_path in self.qmgr_db_paths:
            with db_path.open("rb") as fh:
                db = ESE(fh)
                table = db.table("Jobs")
                # Jobs get ID of files
                # We start by building a dict with all files
                files_dict = self.build_files_dict(db.table("Files"))
                for record in table.records():
                    ctime = None
                    mtime = None
                    mtime_bis = None
                    has_error = False
                    completion_time = None
                    a = record["Blob"]
                    # These bytes indicate if job is an upload/download/upload repy job
                    # For some jobs, especially upload jobs we may have 2 job GUID, we need to skip the first
                    # to parse the structure properly
                    if a[0x1C:0x20] not in [b"\x00\x00\x00\x00", b"\x02\x00\x00\x00", b"\x01\x00\x00\x00"]:
                        a = a[0x10:]
                    entry = c_bits.BitsJobsHeader(a)
                    # Jobs header is followed by a security descriptor section.
                    # Section total length depends on header guid/version
                    # As this is prone to errors, we skip this section.
                    # Especially since next section has a known start sequence
                    # Then we have a list of all files related to this jobs
                    storage_guid_list = a[len(entry) :].split(FILE_LIST_STORAGE_GUID)
                    if len(storage_guid_list) > 1:
                        file_guid_list = c_bits.BitsJobsFileGuidList(storage_guid_list[1])
                    metadata_section_offset = 4
                    if len(storage_guid_list) > 2:
                        job_has_error = storage_guid_list[2][:4] != b"\x00\x00\x00\x00"
                        if job_has_error:
                            # to find job has error section
                            has_error = True
                            metadata_section_offset += self.get_job_error_len(storage_guid_list[2][4:])
                        metadata_section = c_bits.BitsMetadata(storage_guid_list[2][metadata_section_offset:])
                        ctime = wintimestamp(metadata_section.ctime)
                        mtime = wintimestamp(metadata_section.mtime)
                        mtime_bis = wintimestamp(metadata_section.mtime_bis)
                        completion_time = (
                            wintimestamp(metadata_section.completion_time)
                            if metadata_section.completion_time != 0
                            else None
                        )

                    user_sid = entry.sid.strip("\x00")
                    user = None
                    if user_sid and (sid_user_details := self.target.user_details.find(user_sid)):
                        user = sid_user_details.user
                    entry_yielded = False
                    for file_entry in file_guid_list.files_guid:
                        file_guid = uuid.UUID(bytes_le=file_entry)
                        if file_blob := files_dict.get(str(file_guid).lower()):
                            f = (
                                c_bits.DownloadBitsFile(file_blob)
                                if entry.type.name == "DOWNLOAD"
                                else c_bits.UploadBitsFile(file_blob)
                            )
                            transferred_file_mtime = wintimestamp(f.file_mtime) if f.file_mtime != 0 else None
                            yield BitsRecord(
                                job_type=entry.type,
                                state=entry.state,
                                priority=entry.priority,
                                job_id=uuid.UUID(bytes_le=entry.job_id),
                                name=entry.name.strip("\x00"),
                                desc=entry.desc.strip("\x00"),
                                callback_cmd=entry.callback_cmd.strip("\x00"),
                                callback_args=entry.callback_args.strip("\x00"),
                                notify_flag=entry.notify_flag,
                                has_error=has_error,
                                job_ctime=ctime,
                                job_mtime=mtime,
                                job_mtime_bis=mtime_bis,
                                job_completion_time=completion_time,
                                file_guid=file_guid,
                                file_drive=f.drive.strip("\x00"),
                                file_dst=f.dst.strip("\x00"),
                                file_src=f.src.strip("\x00"),
                                file_tmp=f.tmp.strip("\x00"),
                                file_volume=f.volume.strip("\x00"),
                                file_dl_size=f.dl_size,
                                # -1 == Unknown file size
                                file_transfer_size=f.transfer_size if int(f.transfer_size) != -1 else None,
                                transferred_file_mtime=transferred_file_mtime,
                                user_id=user_sid,
                                _user=user,
                                _target=self.target,
                                source=db_path,
                            )
                            entry_yielded = True
                    # if not files related or not found, we yield data that we have
                    if not entry_yielded:
                        yield BitsRecord(
                            job_type=entry.type,
                            state=entry.state,
                            priority=entry.priority,
                            job_id=uuid.UUID(bytes_le=entry.job_id),
                            name=entry.name.strip("\x00"),
                            desc=entry.desc.strip("\x00"),
                            callback_cmd=entry.callback_cmd.strip("\x00"),
                            callback_args=entry.callback_args.strip("\x00"),
                            notify_flag=entry.notify_flag,
                            has_error=has_error,
                            job_ctime=ctime,
                            job_mtime=mtime,
                            job_mtime_bis=mtime_bis,
                            job_completion_time=completion_time,
                            user_id=user_sid,
                            _user=user,
                            _target=self.target,
                            source=db_path,
                        )
