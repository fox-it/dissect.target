import io
import logging
import zipfile

from dissect.util.stream import BufferedStream

from dissect.target.exceptions import FileNotFoundError, FilesystemError
from dissect.target.filesystem import Filesystem, VirtualFile, VirtualFilesystem
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class ZipFilesystem(Filesystem):
    """This Zip filesystem implementation is WIP and
    has only been tested for opening java jar archives.
    Its structure has been copied from the tar filesystem
    implementation.
    """

    __fstype__ = "zip"

    def __init__(self, fh, base=None, case_sensitive=True, zipinfo=None, *args, **kwargs):
        fh.seek(0)

        self.zip = zipfile.ZipFile(fh, mode="r")
        self.base = base.strip("/") if base else ""

        self._fs = VirtualFilesystem(case_sensitive=case_sensitive)

        for member in self.zip.infolist():

            if member.is_dir():
                continue

            mname = member.filename.strip("/")
            if not mname.startswith(self.base):
                continue

            rel_name = mname[len(self.base) :]

            # NOTE: Normally we would check here if the member is a symlink or not,
            # however Python does not have symlink support in the zipfile module.
            # see https://github.com/python/cpython/issues/82102

            file_entry = ZipFilesystemEntry(self, rel_name, member)
            self._fs.map_file_entry(rel_name, file_entry)

        super().__init__(case_sensitive=case_sensitive, *args, **kwargs)

    @staticmethod
    def detect(fh):
        """Detect a zip file on a given file-like object."""
        offset = fh.tell()
        try:
            fh.seek(0)
            zipfile.ZipFile(fileobj=fh, mode="r")
            return True
        except Exception as e:
            log.warning("Failed to detect zip filesystem", exc_info=e)
            return False
        finally:
            fh.seek(offset)

    def get(self, path):
        """Returns a ZipFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path)


class ZipFilesystemEntry(VirtualFile):
    def _resolve(self):
        # NOTE: Normally we would check here if the member is a symlink or not,
        # however Python does not have symlink support in the zipfile module.
        # see https://github.com/python/cpython/issues/82102
        return self

    def open(self):
        """Returns file handle (file-like object)."""
        try:
            f = self.fs.zip.read(self.entry)
            return BufferedStream(io.BytesIO(f), size=self.entry.file_size)
        except Exception as e:
            print(str(e))
            raise FileNotFoundError()

    def is_dir(self):
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.isdir()
        except FilesystemError:
            return False

    def is_file(self):
        """Return whether this entry is a file. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.isfile()
        except FilesystemError:
            return False

    def is_symlink(self):
        """Return whether this entry is a link."""
        # NOTE: Normally we would check here if the member is a symlink or not,
        # however Python does not have symlink support in the zipfile module.
        # see https://github.com/python/cpython/issues/82102
        return False

    def readlink(self):
        """Read the link if this entry is a symlink. Returns a string."""
        return self.entry.linkname

    def readlink_ext(self):
        """Read the link if this entry is a symlink. Returns a filesystem entry."""
        # Can't use the one in VirtualFile as it overrides the FilesystemEntry
        return fsutil.resolve_link(fs=self.fs, entry=self)

    def stat(self):
        """Return the stat information of this entry."""
        return self._resolve().lstat()

    def lstat(self):
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                self.entry.mode,
                0,
                0,
                0,
                self.entry.uid,
                self.entry.gid,
                self.entry.size,
                0,
                self.entry.mtime,
                0,
            ]
        )
