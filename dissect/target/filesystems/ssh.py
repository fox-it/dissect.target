from __future__ import annotations

from typing import TYPE_CHECKING, Any, BinaryIO, Callable

from dissect.util.stream import AlignedStream
from paramiko import AutoAddPolicy, SFTPAttributes, SFTPFile, SSHClient, SSHException, Transport

from dissect.target import exceptions
from dissect.target.filesystems.shell import Dialect, ShellFilesystem, ShellFilesystemEntry, ttl_cache
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class DissectTransport(Transport):
    _CLIENT_ID = "DISSECT"


class SshFilesystem(ShellFilesystem):
    __type__ = "ssh"

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        key_filename: str | None = None,
        key_passphrase: str | None = None,
        isolate: bool = True,
        dialect: str = "auto",
        *args,
        **kwargs,
    ):
        self.client = SSHClient()

        if isolate:
            allow_agent = False
            look_for_keys = False
            self.client.set_missing_host_key_policy(AutoAddPolicy)
        else:
            allow_agent = True
            look_for_keys = True
            self.client.load_system_host_keys()

        self.client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            passphrase=key_passphrase,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
            transport_factory=DissectTransport,
        )

        if dialect in ("sftp", "auto"):
            if (obj := SftpDialect(self)).detect():
                dialect = obj
            elif dialect == "sftp":
                raise exceptions.FilesystemError("SFTP dialect not available on this SSH server")

        super().__init__(dialect, *args, **kwargs)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on SshFilesystem class")

    def execute(self, command: str) -> tuple[bytes, bytes]:
        _, stdout, stderr = self.client.exec_command(command)
        return stdout.read(), stderr.read()

    def get(self, path: str) -> ShellFilesystemEntry:
        try:
            return super().get(path)
        except FileNotFoundError as e:
            raise exceptions.FileNotFoundError(path) from e
        except IOError as e:
            raise exceptions.FilesystemError(path) from e


class SftpDialect(Dialect):
    __type__ = "sftp"

    def __init__(self, fs: SshFilesystem, ttl: int = 60):
        super().__init__(fs)
        try:
            self.sftp = fs.client.open_sftp()
        except SSHException:
            self.sftp = None

        self._do = ttl_cache(ttl)(self._do)

    def _do(self, command: Callable[..., Any], *args) -> Any:
        return command(*args)

    def detect(self) -> bool:
        return self.sftp is not None

    def open(self, path: str, size: int) -> SftpStream:
        return SftpStream(self.sftp.open(path, "r"), size)

    def iterdir(self, path: str) -> Iterator[str]:
        try:
            yield from self._do(self.sftp.listdir, path)
        except FileNotFoundError as e:
            raise exceptions.FileNotFoundError(path) from e
        except IOError as e:
            raise exceptions.FilesystemError(path) from e

    def scandir(self, path: str) -> Iterator[tuple[str, fsutil.stat_result]]:
        try:
            for entry in self.sftp.listdir_iter(path):
                entry_path = fsutil.join(path, entry.filename, alt_separator=self.fs.alt_separator)
                yield entry.filename, self._make_stat_result(entry, entry_path)
        except FileNotFoundError as e:
            raise exceptions.FileNotFoundError(path) from e
        except IOError as e:
            raise exceptions.FilesystemError(path) from e

    def readlink(self, path: str) -> str:
        try:
            return self._do(self.sftp.readlink, path)
        except FileNotFoundError as e:
            raise exceptions.FileNotFoundError(path) from e
        except IOError as e:
            raise exceptions.FilesystemError(path) from e

    def lstat(self, path: str) -> fsutil.stat_result:
        try:
            entry: SFTPAttributes = self._do(self.sftp.lstat, path)
        except FileNotFoundError as e:
            raise exceptions.FileNotFoundError(path) from e
        except IOError as e:
            raise exceptions.FilesystemError(path) from e
        return self._make_stat_result(entry, path)

    def _make_stat_result(self, entry: SFTPAttributes, path: str) -> fsutil.stat_result:
        return fsutil.stat_result(
            [
                entry.st_mode,
                fsutil.generate_addr(path, alt_separator=self.fs.alt_separator),
                id(self.fs),
                1,
                entry.st_uid,
                entry.st_gid,
                entry.st_size,
                entry.st_atime,
                entry.st_mtime,
                0,
            ]
        )


class SftpStream(AlignedStream):
    def __init__(self, fh: SFTPFile, size: int):
        self.fh = fh
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(offset)
        return self.fh.read(length)

    def close(self) -> None:
        self.fh.close()
