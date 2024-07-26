from typing import Generator

from dissect import cstruct
from dissect.util.ts import wintimestamp

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

RecycleBinRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/filesystem/recyclebin",
    [
        ("datetime", "ts"),
        ("path", "path"),
        ("filesize", "filesize"),
        ("path", "deleted_path"),
        ("path", "source"),
    ],
)

c_recyclebin_i = """
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


class RecyclebinPlugin(Plugin):
    """Recyclebin plugin."""

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.recyclebin_parser = cstruct.cstruct()
        self.recyclebin_parser.load(c_recyclebin_i)

    def check_compatible(self) -> None:
        for fs_entry in self.target.fs.path("/").iterdir():
            if self._is_valid_recyclebin(fs_entry):
                return
        raise UnsupportedPluginError("No recycle bins found")

    def _is_valid_recyclebin(self, path: TargetPath) -> bool:
        """Checks wether it is a valid recycle bin path.

        The sysvol is skipped so that there are no duplicated with drive letter that maps to sysvol.
        """

        return path.name != "sysvol" and path.joinpath("$recycle.bin").exists()

    @export(record=RecycleBinRecord)
    def recyclebin(self) -> Generator[RecycleBinRecord, None, None]:
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

        recyclebin_paths = (
            entry.joinpath("$recycle.bin")
            for entry in self.target.fs.path("/").iterdir()
            if self._is_valid_recyclebin(entry)
        )

        for recyclebin in recyclebin_paths:
            yield from self.read_recycle_file(recyclebin)

    def _is_recycle_meta_file(self, path: TargetPath) -> bool:
        """Check wether the path is a recycle bin metadata file"""
        return path.name and path.name.lower().startswith("$i")

    def read_recycle_file(self, path: TargetPath) -> Generator[RecycleBinRecord, None, None]:
        if self._is_recycle_meta_file(path):
            yield self.read_recycle_meta_file(path)
            return

        if path.is_dir() and path.name.startswith("$R"):
            yield from self.read_recycle_deleted_folder(path)
            return

        if path.is_dir():
            for new_file in path.iterdir():
                yield from self.read_recycle_file(new_file)

    def read_recycle_meta_file(self, bin_path: TargetPath) -> RecycleBinRecord:
        data = bin_path.read_bytes()

        header = self.select_header(data)
        entry = header(data)

        sid = self.find_sid(bin_path)
        source_path = str(bin_path).lstrip("/")
        deleted_path = str(bin_path.parent / bin_path.name.replace("$I", "$R")).lstrip("/")

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

    def read_recycle_deleted_folder(self, folder_path: TargetPath) -> RecycleBinRecord:
        # Generally speaking when deleting a file, the $R* file is the actual renamed deleted file.
        # This is however also the case for deleted folders. When a folder is deleted,
        # it is also renamed and placed here (with original recursive content).
        #
        # This function will create RecycleBin records for each file in a deleted folder.

        meta_file = self.target.fs.path(str(folder_path.parent / folder_path.name.replace("$R", "$I")).lstrip("/"))
        if not meta_file.exists():
            return

        meta_data = meta_file.read_bytes()
        header = self.select_header(meta_data)
        entry = header(meta_data)

        sid = self.find_sid(folder_path)
        original_folder_path = self.target.fs.path(entry.filename.rstrip("\x00"))

        user_details = self.target.user_details.find(sid=sid)
        user = user_details.user if user_details else None
        for parent_path, _, childs in folder_path.walk():
            for child in childs:
                child_path = self.target.fs.path(f"{str(parent_path).lstrip('/')}/{child}")
                original_parent_of_child = original_folder_path / str(parent_path).split(folder_path.name)[1].lstrip(
                    "/"
                )
                yield RecycleBinRecord(
                    ts=wintimestamp(entry.timestamp),
                    path=original_parent_of_child / child,
                    source=meta_file,
                    filesize=child_path.stat().st_size,
                    deleted_path=child_path,
                    _target=self.target,
                    _user=user,
                )

    def find_sid(self, path: TargetPath) -> str:
        parent_path = path.parent
        if parent_path.name.lower() == "$recycle.bin":
            return "unknown"
        return parent_path.name

    def select_header(self, data: bytes) -> cstruct.Structure:
        """Selects the correct header based on the version field in the header"""

        header_version = self.recyclebin_parser.uint64(data[:8])
        if header_version == 2:
            return self.recyclebin_parser.header_v2
        else:
            return self.recyclebin_parser.header_v1
