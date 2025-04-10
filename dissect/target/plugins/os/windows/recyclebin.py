from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

RecycleBinRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/filesystem/recyclebin",
    [
        ("datetime", "ts"),
        ("path", "path"),
        ("filesize", "filesize"),
        ("path", "deleted_path"),
        ("string", "source"),
    ],
)

recyclebin_def = """
struct header_v1 {
    int64    version;
    int64    file_size;
    int64    timestamp;
    wchar    filename[260];
};
struct header_v2 {
    int64    version;
    int64    file_size;
    int64    timestamp;
    int32    filename_length;
    wchar    filename[filename_length];
};
"""

c_recyclebin = cstruct().load(recyclebin_def)


class RecyclebinPlugin(Plugin):
    """Recyclebin plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.recyclebin_paths = []
        for fs_entry in self.target.fs.path("/").iterdir():
            if self._is_valid_recyclebin(fs_entry):
                self.recyclebin_paths.append(fs_entry.joinpath("$recycle.bin"))

    def check_compatible(self) -> None:
        if not self.recyclebin_paths:
            raise UnsupportedPluginError("No recycle bins found")

    def _is_valid_recyclebin(self, path: TargetPath) -> bool:
        """Checks wether it is a valid recycle bin path.

        The sysvol is skipped so that there are no duplicated with drive letter that maps to sysvol.
        """

        return path.name != "sysvol" and path.joinpath("$recycle.bin").exists()

    @export(record=RecycleBinRecord)
    def recyclebin(self) -> Iterator[RecycleBinRecord]:
        """
        Return files located in the recycle bin ($Recycle.Bin).

        Yields RecycleBinRecords with fields:

        .. code-block:: text

          hostname (string): The target hostname
          domain (string): The target domain
          ts (datetime): The time of deletion
          path (uri): The file original location before deletion
          filesize (filesize): Filesize of the deleted file
          sid (string): SID of the user deleted the file, parsed from $I filepath
          user (string): Username matching SID, lookup using Dissect user plugin
          deleted_path (uri): Location of the deleted file after deletion $R file
          source (uri): Location of $I meta file on disk
        """

        for recyclebin in self.recyclebin_paths:
            yield from self.read_recycle_bin(recyclebin)

    def _is_recycle_file(self, path: TargetPath) -> bool:
        """Check wether the path is a recycle bin metadata file."""
        return path.name and path.name.lower().startswith("$i")

    def read_recycle_bin(self, bin_path: TargetPath) -> Iterator[RecycleBinRecord]:
        if self._is_recycle_file(bin_path):
            yield self.read_bin_file(bin_path)
            return

        if bin_path.is_dir():
            for new_file in bin_path.iterdir():
                yield from self.read_recycle_bin(new_file)

    def read_bin_file(self, bin_path: TargetPath) -> RecycleBinRecord:
        data = bin_path.read_bytes()

        header = self.select_header(data)
        entry = header(data)

        sid = self.find_sid(bin_path)
        source_path = str(bin_path).lstrip("/")
        deleted_path = str(bin_path.parent / bin_path.name.replace("/$i", "/$r")).lstrip("/")

        user_details = self.target.user_details.find(sid=sid)
        user = user_details.user if user_details else None

        return RecycleBinRecord(
            ts=wintimestamp(entry.timestamp),
            path=self.target.fs.path(entry.filename.rstrip("\x00")),
            source=self.target.fs.path(source_path),
            filesize=entry.file_size,
            deleted_path=self.target.fs.path(deleted_path),
            _target=self.target,
            _user=user,
        )

    def find_sid(self, path: TargetPath) -> str:
        parent_path = path.parent
        if parent_path.name.lower() == "$recycle.bin":
            return "unknown"
        return parent_path.name

    def select_header(self, data: bytes) -> c_recyclebin.header_v1 | c_recyclebin.header_v2:
        """Selects the correct header based on the version field in the header."""

        header_version = c_recyclebin.uint64(data[:8])
        if header_version == 2:
            return c_recyclebin.header_v2
        return c_recyclebin.header_v1
