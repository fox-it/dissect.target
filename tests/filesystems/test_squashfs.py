from __future__ import annotations

import platform

import pytest

from dissect.target.filesystems.squashfs import SquashFSFilesystem
from tests._utils import absolute_path


@pytest.mark.parametrize("type", ["gzip", "gzip-opts", "lz4", "lzma", "lzo", "xz", "zstd"])
def test_filesystem_squashfs(type: str) -> None:
    """Test if we detect and correctly iterate SquashFS filesystems."""

    if type == "lzma" and platform.system() == "Windows":
        pytest.skip(reason="SquashFS LZMA misbehaves on Windows")

    sqfs_bin = absolute_path(f"_data/filesystems/squashfs/{type}.sqfs")

    with sqfs_bin.open("rb") as fh:
        assert SquashFSFilesystem.detect(fh)

        fs = SquashFSFilesystem(fh)

        assert [f.name for f in fs.path("/").iterdir()] == [
            "dir",
            "file-with-xattr",
            "large-file",
            "small-file",
            "symlink-1",
            "symlink-2",
            "symlink-with-xattr",
        ]

        assert fs.path("/dir").is_dir()
        assert fs.path("/symlink-2").is_symlink()
        assert fs.path("/dir/file_99").is_file()
        assert fs.path("/small-file").read_bytes() == b"contents\n"
        assert fs.path("/symlink-2").resolve().as_posix() == "/dir/file_69"

        stat = fs.path("/large-file").lstat()
        assert stat.st_mode == 0o100644
        assert stat.st_ino == 103
        assert stat.st_nlink == 1
        assert stat.st_uid == 1000
        assert stat.st_gid == 1000
        assert stat.st_size == 4177920
        assert stat.st_mtime == 1670266447.0
