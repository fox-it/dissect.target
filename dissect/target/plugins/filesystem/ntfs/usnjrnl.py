from typing import Iterator

from dissect.ntfs.c_ntfs import segment_reference
from flow.record.fieldtypes import uri

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter

UsnjrnlRecord = TargetRecordDescriptor(
    "filesystem/ntfs/usnjrnl",
    [
        ("datetime", "ts"),
        ("varint", "usn"),
        ("string", "segment"),
        ("uri", "path"),
        ("string", "reason"),
        ("uint32", "security_id"),
        ("string", "source"),
        ("string", "attr"),
        ("uint16", "major"),
        ("uint16", "minor"),
    ],
)


class UsnjrnlPlugin(Plugin):
    def check_compatible(self):
        pass

    @export(record=UsnjrnlRecord)
    def usnjrnl(self) -> Iterator[UsnjrnlRecord]:
        """Return the UsnJrnl entries of all NTFS filesystems.

        The Update Sequence Number Journal (UsnJrnl) is a feature of an NTFS file system and contains information about
        filesystem activities. Each volume has its own UsnJrnl.

        References:
            - https://en.wikipedia.org/wiki/USN_Journal
            - https://velociraptor.velocidex.com/the-windows-usn-journal-f0c55c9010e
        """
        target = self.target
        for fs in self.target.filesystems:
            if fs.__fstype__ != "ntfs":
                continue

            usnjrnl = fs.ntfs.usnjrnl
            if not usnjrnl:
                continue

            drive_letter = get_drive_letter(self.target, fs)
            for record in usnjrnl.records():
                try:
                    ts = None
                    try:
                        ts = record.timestamp
                    except ValueError:
                        target.log.error(
                            "Error occured during parsing of timestamp in usnjrnl: %x", record.record.TimeStamp
                        )

                    path = f"{drive_letter}{record.full_path}"
                    segment = segment_reference(record.record.FileReferenceNumber)
                    yield UsnjrnlRecord(
                        ts=ts,
                        segment=f"{segment}#{record.FileReferenceNumber.SequenceNumber}",
                        path=uri.from_windows(path),
                        usn=record.Usn,
                        reason=str(record.Reason).replace("USN_REASON.", ""),
                        attr=str(record.FileAttributes).replace("FILE_ATTRIBUTE.", ""),
                        source=str(record.SourceInfo).replace("USN_SOURCE.", ""),
                        security_id=record.SecurityId,
                        major=record.MajorVersion,
                        minor=record.MinorVersion,
                        _target=target,
                    )
                except Exception as e:
                    target.log.error("Error during processing of usnjrnl record: %s", record.record, exc_info=e)
