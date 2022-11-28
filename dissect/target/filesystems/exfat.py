import stat

from dissect.fat import exfat
from dissect.util.stream import RunlistStream
from dissect.util.ts import UTC, dostimestamp

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class ExfatFilesystem(Filesystem):
    __fstype__ = "exfat"

    def __init__(self, fh=None, *args, **kwargs):
        self.exfat = exfat.EXFAT(fh=fh)
        self.cluster_size = self.exfat.cluster_size
        super().__init__(case_sensitive=False, alt_separator="\\", *args, **kwargs)

    @staticmethod
    def detect(fh):
        try:
            offset = fh.tell()
            fh.seek(0)
            signature = fh.read(11)  # exFAT sig should be in the first 10 bytes - 3 from jump boot
            fh.seek(offset)

            return signature[3:] == b"EXFAT   "
        except Exception:  # noqa
            return False

    def get(self, path):
        """Returns a ExfatFilesystemEntry object corresponding to the given pathname"""
        try:
            dirname, file = fsutil.split(path, alt_separator=self.alt_separator)
            if path == dirname and not file:
                entry = self._gen_dict_extract(dirname)
            elif dirname and file:
                entry = self._gen_dict_extract(dirname)[1][file]
            else:
                entry = self._gen_dict_extract(file)
            return ExfatFilesystemEntry(self, entry, file)
        except TypeError as e:
            raise FileNotFoundError(path, cause=e)
        except KeyError as e:
            raise FileNotFoundError(path, cause=e)

    def open(self, path):
        """Return file handle (file like object)"""
        return self.get(path).open()

    def iterdir(self, path):
        """List the directory contents of a directory. Returns a generator of strings."""
        try:
            files = self.exfat.files.keys() if path == "/" else self._gen_dict_extract(path)[1].keys()
        except AttributeError as e:
            raise NotADirectoryError(path, cause=e)
        except TypeError as e:
            raise FileNotFoundError(path, cause=e)

        for file in files:
            yield file

    def scandir(self, path):
        """List the directory contents of a directory. Returns a generator of filesystem entries."""

        try:
            paths = []
            files = self.exfat.files.keys() if path == "/" else self._gen_dict_extract(path)[1].keys()
        except AttributeError as e:
            raise NotADirectoryError(path, cause=e)
        except TypeError as e:
            raise FileNotFoundError(path, cause=e)

        for file in files:
            if path == "/":
                yield self.get(file)
            else:
                paths.append(fsutil.join(path, file, alt_separator=self.alt_separator))

            for path in paths:
                yield self.get(path)

    def stat(self, path):
        """Returns POSIX file status results"""
        return self.get(path).stat()

    def _gen_dict_extract(self, key, var=None):
        var = self.exfat.files if var is None else var

        if hasattr(var, "items"):
            for k, v in var.items():
                if k == key:
                    return v
                if isinstance(v, dict):
                    for result in self._gen_dict_extract(key, v):
                        return result


class ExfatFilesystemEntry(FilesystemEntry):
    def __init__(self, fs, entry=None, path=None):
        super().__init__(fs, path, entry)
        self.fs = fs
        self.entry = entry[0]
        self.files = entry[1]
        self.name = path
        self.size = self.entry.stream.data_length
        self.cluster = self.entry.stream.location

    def __repr__(self):
        return repr(self.entry)

    def is_symlink(self):
        """Return whether this entry is a link."""
        return False

    def is_dir(self):
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        return bool(self.entry.metadata.attributes.directory)

    def is_file(self):
        """Return whether this entry is a file. Resolves symlinks when possible."""
        return not self.is_dir()

    def get(self, path):
        """Get a filesystem entry relative from the current one."""
        if self.is_dir():
            entry = self.files[path]
            return ExfatFilesystemEntry(self.fs, entry, path)
        else:
            raise NotADirectoryError(self.name)

    def iterdir(self):
        """List the directory contents of a directory. Returns a generator of strings."""
        if self.is_dir():
            files = self.files.keys()

            for file in files:
                yield file
        else:
            raise NotADirectoryError(self.name)

    def scandir(self):
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if self.is_dir():
            files = self.files.keys()

            for file in files:
                yield self.get(file)
        else:
            raise NotADirectoryError(self.name)

    def stat(self):
        """Return the stat information of this entry."""
        fe = self.entry
        size = fe.stream.data_length
        addr = fe.stream.location

        # exfat stores additional offsets for ctime and mtime to get 10 millisecond precision
        fe = fe.metadata

        # all timestamps are recorded in local time. the utc offset (of the system generating the timestamp in question)
        # is recorded in the associated tz byte
        c_tz = UTC(self.fs.exfat._utc_timezone(fe.create_timezone))  # noqa
        m_tz = UTC(self.fs.exfat._utc_timezone(fe.modified_timezone))  # noqa
        a_tz = UTC(self.fs.exfat._utc_timezone(fe.access_timezone))  # noqa

        ctime = dostimestamp(fe.create_time, fe.create_offset).replace(tzinfo=c_tz)
        mtime = dostimestamp(fe.modified_time, fe.modified_offset).replace(tzinfo=m_tz)
        atime = dostimestamp(fe.access_time).replace(tzinfo=a_tz)

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
            addr,
            id(self.fs),
            0,
            0,
            0,
            size,
            atime.timetuple().timestamp(),
            mtime.timetuple().timestamp(),
            ctime.timetuple().timestamp(),
        ]
        return fsutil.stat_result(st_info)

    def open(self):
        """Returns file handle (file like object)"""
        if self.entry.stream.flags.not_fragmented:
            runlist = self.fs.exfat.runlist(self.cluster, True, self.size)
        else:
            runlist = self.fs.exfat.runlist(self.cluster, False)
        fh = RunlistStream(self.fs.exfat.filesystem, runlist, self.size, self.fs.cluster_size)
        return fh

    def readlink(self):
        return TypeError()

    def readlink_ext(self):
        return TypeError()

    def lstat(self):
        return TypeError()

    def attr(self):
        return TypeError()

    def lattr(self):
        return TypeError()
