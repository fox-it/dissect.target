from __future__ import annotations

import logging
import time

import pytest

from dissect.target.filesystems.shell import LinuxDialect, ShellFilesystem, ttl_cache


def test_ttl_cache() -> None:
    @ttl_cache(ttl=1)
    def func() -> float:
        return time.time()

    result1 = func()
    time.sleep(0.5)
    result2 = func()
    assert result1 == result2  # Cached result

    time.sleep(1)
    result3 = func()
    assert result1 != result3  # Cache expired


class MockShellFilesystem(ShellFilesystem):
    __type__ = "mock-shell"

    def __init__(self, queue: list[tuple[str, tuple[bytes, bytes]]] | None = None, *args, **kwargs):
        self.queue = queue or []
        super().__init__(*args, **kwargs)

    def execute(self, command: str) -> tuple[bytes, bytes]:
        assert self.queue, f"No more commands in queue, expected: {command}"

        expected_command, (stdout, stderr) = self.queue.pop(0)
        assert command == expected_command
        return stdout, stderr


def test_shell_dialect_linux(caplog: pytest.LogCaptureFixture) -> None:
    fs = MockShellFilesystem(dialect="linux")

    fs.queue.append(
        (
            "stat '/'",
            (
                b"  File: /\n  Size: 254       \tBlocks: 0          IO Block: 4096   directory\nDevice: 0,38\tInode: 901167      Links: 1\nAccess: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: 2025-05-16 22:42:18.000000000 +0200\nModify: 2025-08-22 11:43:56.903048665 +0200\nChange: 2025-08-22 11:43:56.903048665 +0200\n Birth: 2025-05-19 13:58:46.909076358 +0200",  # noqa: E501
                b"",
            ),
        )
    )
    entry = fs.path("/")
    assert entry.is_dir()
    assert entry.stat().st_mode & 0o777 == 0o755
    assert entry.stat().st_ino == 901167
    assert entry.stat().st_dev == 0x26
    assert entry.stat().st_nlink == 1
    assert entry.stat().st_uid == 0
    assert entry.stat().st_gid == 0
    assert entry.stat().st_size == 254
    assert entry.stat().st_atime == 1747428138.0
    assert entry.stat().st_mtime == 1755855836.903048
    assert entry.stat().st_ctime == 1755855836.903048
    assert entry.stat().st_birthtime == 1747655926.909076

    fs.queue.append(
        (
            "find '/'/ -mindepth 1 -maxdepth 1 -print0",
            (
                b"//.profile\x00//afs\x00//bin\x00//boot\x00//dev\x00//etc\x00//home\x00//lib\x00//lib64\x00//media\x00//mnt\x00//opt\x00//proc\x00//root\x00//run\x00//sbin\x00//srv\x00//sys\x00//tmp\x00//usr\x00//var\x00//private\x00//.autorelabel\x00",
                b"",
            ),
        )
    )
    assert entry.get().listdir() == [
        ".profile",
        "afs",
        "bin",
        "boot",
        "dev",
        "etc",
        "home",
        "lib",
        "lib64",
        "media",
        "mnt",
        "opt",
        "proc",
        "root",
        "run",
        "sbin",
        "srv",
        "sys",
        "tmp",
        "usr",
        "var",
        "private",
        ".autorelabel",
    ]

    fs.queue.append(
        (
            "stat '/media'",
            (
                b"  File: /media\n  Size: 0         \tBlocks: 0          IO Block: 4096   directory\nDevice: 0,38\tInode: 902284      Links: 1\nAccess: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: 2024-07-17 02:00:00.000000000 +0200\nModify: 2024-07-17 02:00:00.000000000 +0200\nChange: 2025-05-19 13:58:46.972077140 +0200\n Birth: 2025-05-19 13:58:46.930076618 +0200\n",  # noqa: E501
                b"",
            ),
        )
    )
    fs.queue.append(
        (
            "find '/media'/ -mindepth 1 -maxdepth 1 -print0",
            (b"", b""),
        )
    )
    assert list(entry.joinpath("media").get().scandir()) == []

    fs.queue.append(
        (
            "stat '/nonexistent'",
            (b"", b"stat: cannot statx '/nonexistent': No such file or directory\n"),
        )
    )
    with pytest.raises(FileNotFoundError, match="Failed to list directory '/nonexistent': No such file or directory"):
        fs.path("/nonexistent").stat()

    fs.queue.append(
        (
            "stat '/tmp/srt'",
            (
                b"  File: /tmp/srt\n  Size: 5         \tBlocks: 8          IO Block: 4096   regular file\nDevice: 0,46\tInode: 7           Links: 1\nAccess: (0644/-rw-r--r--)  Uid: (  501/    erik)   Gid: (  501/    erik)\nAccess: 2025-08-22 12:06:48.748059407 +0200\nModify: 2025-08-22 12:06:48.748059407 +0200\nChange: 2025-08-22 12:06:48.748059407 +0200\n Birth: 2025-08-22 12:06:48.748059407 +0200\n",  # noqa: E501
                b"",
            ),
        )
    )
    fs.queue.append(
        (
            "dd if='/tmp/srt' bs=8192 skip=0 count=1 status=none",
            (b"\xf0\x9f\xab\xb6\n", b""),
        )
    )
    assert fs.path("/tmp/srt").is_file()
    with fs.path("/tmp/srt").open() as fh:
        assert fh.read() == "🫶\n".encode()

    fs.queue.append(
        (
            "stat '/tmp/kusjes-van'",
            (
                b"  File: /tmp/kusjes-van -> srt\n  Size: 3         \tBlocks: 0          IO Block: 4096   symbolic link\nDevice: 0,46\tInode: 8           Links: 1\nAccess: (0777/lrwxrwxrwx)  Uid: (  501/    erik)   Gid: (  501/    erik)\nAccess: 2025-08-22 12:09:51.420607298 +0200\nModify: 2025-08-22 12:09:50.574609356 +0200\nChange: 2025-08-22 12:09:50.574609356 +0200\n Birth: 2025-08-22 12:09:50.574609356 +0200\n",  # noqa: E501
                b"",
            ),
        )
    )
    fs.queue.append(
        (
            "readlink -n '/tmp/kusjes-van'",
            (b"srt", b""),
        )
    )
    assert fs.path("/tmp/kusjes-van").is_symlink()
    assert fs.readlink("/tmp/kusjes-van") == "srt"

    fs.queue.append(
        (
            "stat '/dev/vda'",
            (
                b"  File: /dev/vda\n  Size: 0         \tBlocks: 0          IO Block: 512    block special file\nDevice: 0,6\tInode: 144         Links: 1     Device type: 254,0\nAccess: (0660/brw-rw----)  Uid: (    0/    root)   Gid: (    6/    disk)\nAccess: 2025-08-22 11:43:57.268955207 +0200\nModify: 2025-08-22 11:43:57.268955207 +0200\nChange: 2025-08-22 11:43:57.268955207 +0200\n Birth: 1970-01-01 01:00:00.049000000 +0100\n",  # noqa: E501
                b"",
            ),
        )
    )
    fs.queue.append(
        (
            "blockdev --getsize64 '/dev/vda'",
            (b"", b"blockdev: cannot open /dev/vda: Permission denied\n"),
        )
    )
    with caplog.at_level(logging.DEBUG):
        fs.path("/dev/vda").stat()

        assert "Failed to get size of block device '/dev/vda': Filesystem error: Permission denied" in caplog.text


def test_shell_dialect_linux_fast() -> None:
    fs = MockShellFilesystem(dialect="linux-fast")

    result = """  File: /tmp/kusjes-van -> srt
  Size: 3         	Blocks: 0          IO Block: 4096   symbolic link
Device: 0,46	Inode: 8           Links: 1
Access: (0777/lrwxrwxrwx)  Uid: (  501/    erik)   Gid: (  501/    erik)
Access: 2025-08-22 12:09:51.420607298 +0200
Modify: 2025-08-22 12:09:50.574609356 +0200
Change: 2025-08-22 12:09:50.574609356 +0200
 Birth: 2025-08-22 12:09:50.574609356 +0200
  File: /tmp/srt
  Size: 5         	Blocks: 8          IO Block: 4096   regular file
Device: 0,46	Inode: 7           Links: 1
Access: (0644/-rw-r--r--)  Uid: (  501/    erik)   Gid: (  501/    erik)
Access: 2025-08-22 12:08:46.956764097 +0200
Modify: 2025-08-22 12:06:48.748059407 +0200
Change: 2025-08-22 12:06:48.748059407 +0200
 Birth: 2025-08-22 12:06:48.748059407 +0200
"""

    fs.queue.append(
        (
            "stat '/tmp'",
            (
                b"  File: /tmp\n  Size: 180       \tBlocks: 0          IO Block: 4096   directory\nDevice: 0,46\tInode: 1           Links: 6\nAccess: (1777/drwxrwxrwt)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: 2025-08-22 12:22:52.380639649 +0200\nModify: 2025-08-22 12:13:09.645198825 +0200\nChange: 2025-08-22 12:13:09.645198825 +0200\n Birth: 2025-08-22 11:43:56.918048665 +0200\n",  # noqa: E501
                b"",
            ),
        )
    )
    fs.queue.append(
        (
            "stat '/tmp'/*",
            (result.encode(), b""),
        )
    )
    fs.path("/tmp")
    assert [entry.path for entry in fs.scandir("/tmp")] == ["/tmp/kusjes-van", "/tmp/srt"]


def test_shell_dialect_auto() -> None:
    fs = MockShellFilesystem(
        [
            # Fail linux-fast detection
            (
                "stat '/'*",
                (b"", b"stat: cannot statx '/*': You shall not pass!\n"),
            ),
            # Succeed linux detection
            (
                "find '/'/ -mindepth 1 -maxdepth 1 -print0",
                (b"//something\x00", b""),
            ),
        ],
        dialect="auto",
    )
    assert isinstance(fs.dialect, LinuxDialect)
