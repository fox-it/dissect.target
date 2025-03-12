from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter


def format_info(
    md5=0, name=0, inode=0, mode_as_string=0, uid=0, gid=0, size=0, atime=0, mtime=0, ctime=0, crtime=0
) -> str:
    return f"{md5}|{name}|{inode}|{mode_as_string}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}"


class MftBodyPlugin(Plugin):
    """NTFS MFT body plugin."""

    def check_compatible(self) -> None:
        ntfs_filesystems = [fs for fs in self.target.filesystems if fs.__type__ == "ntfs"]
        if not len(ntfs_filesystems):
            raise UnsupportedPluginError("No NTFS filesystem found")

    @export(output="yield")
    def mft_body(self) -> Iterator[str]:
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

            # If this filesystem is a "fake" NTFS filesystem, used to enhance a
            # VirtualFilesystem, The driveletter (more accurate mount point)
            # returned will be that of the VirtualFilesystem. This makes sure
            # the paths returned in the records are actually reachable.
            drive_letter = get_drive_letter(self.target, fs)

            for record in fs.ntfs.mft.segments():
                # Just to make it clear when something is a file or a dir.
                file_mode = "d/drwxrwxrwx" if record.is_dir() else "r/rrwxrwxrwx"

                try:
                    for path in record.full_paths(False):
                        path = f"{drive_letter}{path}"

                        for attribute in record.attributes.STANDARD_INFORMATION:
                            yield format_info(
                                name=path,
                                atime=int(attribute.last_access_time.timestamp()),
                                mtime=int(attribute.last_modification_time.timestamp()),
                                ctime=int(attribute.last_change_time.timestamp()),
                                crtime=int(attribute.creation_time.timestamp()),
                                mode_as_string=file_mode,
                            )
                except Exception as e:
                    self.target.log.warning(
                        "An error occured parsing the $STANDARD_INFORMATION attribute of MFT segment %d: %s",
                        record.segment,
                        str(e),
                    )

                try:
                    for attribute in record.attributes.FILE_NAME:
                        path = f"{drive_letter}{attribute.full_path()} ($FILE_NAME)"  # fls like output
                        yield format_info(
                            name=path,
                            atime=int(attribute.last_access_time.timestamp()),
                            mtime=int(attribute.last_modification_time.timestamp()),
                            ctime=int(attribute.last_change_time.timestamp()),
                            crtime=int(attribute.creation_time.timestamp()),
                            size=attribute.file_size,
                            mode_as_string=file_mode,
                        )
                except Exception as e:
                    self.target.log.warning(
                        "An error occured parsing the $FILE_NAME attribute of MFT segment %d: %s",
                        record.segment,
                        str(e),
                    )
