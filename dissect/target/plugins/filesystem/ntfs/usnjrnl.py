from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.ntfs.c_ntfs import segment_reference

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter

if TYPE_CHECKING:
    from collections.abc import Iterator

UsnjrnlRecord = TargetRecordDescriptor(
    "filesystem/ntfs/usnjrnl",
    [
        ("datetime", "ts"),
        ("varint", "usn"),
        ("string", "segment"),
        ("path", "path"),
        ("string", "reason"),
        ("uint32", "security_id"),
        ("string", "source"),
        ("string", "attr"),
        ("uint16", "major"),
        ("uint16", "minor"),
    ],
)


class UsnjrnlPlugin(Plugin):
    """NFTS UsnJrnl plugin."""

    def check_compatible(self) -> None:
        if not any(fs for fs in self.target.filesystems if fs.__type__ == "ntfs"):
            raise UnsupportedPluginError("No NTFS filesystem(s) found on target")

    @export(record=UsnjrnlRecord)
    def usnjrnl(self) -> Iterator[UsnjrnlRecord]:
        """Return the UsnJrnl entries of all NTFS filesystems.

        The Update Sequence Number Journal (UsnJrnl) is a feature of an NTFS file system and contains information about
        filesystem activities. Each volume has its own UsnJrnl.

        If the filesystem is part of a virtual NTFS filesystem (a ``VirtualFilesystem`` with the UsnJrnl
        properties added to it through a "fake" ``NtfsFilesystem``), the paths returned in the UsnJrnl records
        are based on the mount point of the ``VirtualFilesystem``. This ensures that the proper original drive
        letter is used when available.
        When no drive letter can be determined, the path will show as e.g. ``\\$fs$\\fs0``.

        References:
            - https://en.wikipedia.org/wiki/USN_Journal
            - https://velociraptor.velocidex.com/the-windows-usn-journal-f0c55c9010e
        """
        target = self.target
        for fs in self.target.filesystems:
            if fs.__type__ != "ntfs":
                continue

            usnjrnl = fs.ntfs.usnjrnl
            if not usnjrnl:
                continue

            # If this filesystem is a "fake" NTFS filesystem, used to enhance a
            # VirtualFilesystem, The driveletter (more accurate mount point)
            # returned will be that of the VirtualFilesystem. This makes sure
            # the paths returned in the records are actually reachable.
            drive_letter = get_drive_letter(self.target, fs)
            for record in usnjrnl.records():
                try:
                    ts = None
                    try:
                        ts = record.timestamp
                    except ValueError as e:
                        target.log.error(  # noqa: TRY400
                            "Error occured during parsing of timestamp in usnjrnl: %x", record.record.TimeStamp
                        )
                        target.log.debug("", exc_info=e)

                    path = f"{drive_letter}{record.full_path}"
                    segment = segment_reference(record.record.FileReferenceNumber)
                    yield UsnjrnlRecord(
                        ts=ts,
                        segment=f"{segment}#{record.FileReferenceNumber.SequenceNumber}",
                        path=self.target.fs.path(path),
                        usn=record.Usn,
                        reason=str(record.Reason).replace("USN_REASON.", ""),
                        attr=str(record.FileAttributes).replace("FILE_ATTRIBUTE.", ""),
                        source=str(record.SourceInfo).replace("USN_SOURCE.", ""),
                        security_id=record.SecurityId,
                        major=record.MajorVersion,
                        minor=record.MinorVersion,
                        _target=target,
                    )
                except Exception as e:  # noqa: PERF203
                    target.log.error("Error during processing of usnjrnl record: %s", record.record)  # noqa: TRY400
                    target.log.debug("", exc_info=e)
