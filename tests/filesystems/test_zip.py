from __future__ import annotations

import io
import zipfile

import pytest

from dissect.target.exceptions import (
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystems.zip import ZipFilesystem, ZipFilesystemEntry


def _mkdir(zf: zipfile.ZipFile, name: str) -> None:
    # There's no easy way to make a directory with Python zipfile, so copy what zipfile.py does
    zinfo = zipfile.ZipInfo(name)
    zinfo.compress_size = 0
    zinfo.CRC = 0
    zinfo.external_attr = ((0o40000 | 511) & 0xFFFF) << 16
    zinfo.file_size = 0
    zinfo.external_attr |= 0x10

    with zf._lock:
        if zf._seekable:
            zf.fp.seek(zf.start_dir)
        zinfo.header_offset = zf.fp.tell()  # Start of header bytes
        if zinfo.compress_type == zipfile.ZIP_LZMA:
            # Compressed data includes an end-of-stream (EOS) marker
            zinfo.flag_bits |= zipfile._MASK_COMPRESS_OPTION_1

        zf._writecheck(zinfo)
        zf._didModify = True

        zf.filelist.append(zinfo)
        zf.NameToInfo[zinfo.filename] = zinfo
        zf.fp.write(zinfo.FileHeader(False))
        zf.start_dir = zf.fp.tell()


def _create_zip(prefix: str = "", zip_dir: bool = True) -> io.BytesIO:
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")

    if prefix and zip_dir:
        cur = []
        for p in prefix.strip("/").split("/"):
            cur.append(p)
            _mkdir(zf, "/".join(cur))

    zf.writestr(zipfile.ZipInfo(f"{prefix}file_1"), "file 1 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_2"), "file 2 contents")

    if zip_dir:
        _mkdir(zf, f"{prefix}dir/")

    for i in range(100):
        zf.writestr(f"{prefix}dir/{i}", f"contents {i}")

    symlink = zipfile.ZipInfo(f"{prefix}symlink_dir")
    symlink.external_attr = 0o120777 << 16
    zf.writestr(symlink, "dir/")

    symlink = zipfile.ZipInfo(f"{prefix}symlink_file")
    symlink.external_attr = 0o120777 << 16
    zf.writestr(symlink, "file_1")

    zf.close()
    buf.seek(0)
    return buf


@pytest.fixture
def zip_simple() -> io.BytesIO:
    return _create_zip()


@pytest.fixture
def zip_base() -> io.BytesIO:
    return _create_zip("base/")


@pytest.fixture
def zip_relative() -> io.BytesIO:
    return _create_zip("./", False)


@pytest.fixture
def zip_relative_dir() -> io.BytesIO:
    return _create_zip("./")


@pytest.fixture
def zip_virtual_dir() -> io.BytesIO:
    return _create_zip("", False)


@pytest.mark.parametrize(
    ("obj", "base"),
    [
        ("zip_simple", ""),
        ("zip_base", "base/"),
        ("zip_relative", ""),
        ("zip_relative_dir", ""),
        ("zip_virtual_dir", ""),
    ],
)
def test_filesystems_zip(obj: str, base: str, request: pytest.FixtureRequest) -> None:
    fh = request.getfixturevalue(obj)

    assert ZipFilesystem.detect(fh)

    fs = ZipFilesystem(fh, base)
    assert isinstance(fs, ZipFilesystem)

    assert len(fs.listdir("/")) == 5

    assert fs.get("./file_1").open().read() == b"file 1 contents"
    assert fs.get("./file_2").open().read() == b"file 2 contents"
    assert fs.get("./symlink_file").open().read() == b"file 1 contents"
    assert len(list(fs.glob("./dir/*"))) == 100
    assert len(list(fs.glob("./symlink_dir/*"))) == 100

    zfile = fs.get("./file_1")
    zdir = fs.get("./dir")
    zsymd = fs.get("./symlink_dir")
    zsymf = fs.get("./symlink_file")

    assert zfile.is_file()
    assert not zfile.is_dir()
    assert not zfile.is_symlink()

    with pytest.raises(NotADirectoryError):
        list(zfile.iterdir())

    with pytest.raises(NotADirectoryError):
        next(zfile.scandir())

    with pytest.raises(NotASymlinkError):
        zfile.readlink()

    assert zdir.is_dir()
    assert not zdir.is_file()
    assert not zdir.is_symlink()
    assert len(list(zdir.iterdir())) == 100
    assert len(list(zdir.scandir())) == 100

    with pytest.raises(IsADirectoryError):
        zdir.open()

    assert zsymd.is_dir()
    assert not zsymd.is_file()
    assert zsymd.is_symlink()
    assert zsymd.readlink() == "dir/"

    assert not zsymf.is_dir()
    assert zsymf.is_file()
    assert zsymf.is_symlink()
    assert zsymf.readlink() == "file_1"

    file1 = zdir.get("1")
    assert file1.is_file()
    assert not file1.is_dir()
    assert not file1.is_symlink()
    assert file1.open().read() == b"contents 1"

    assert file1.stat() == zsymd.get("1").stat()

    assert zfile.stat().st_mode == 0o100600
    assert zfile.stat(follow_symlinks=False) == zfile.lstat()

    if isinstance(zdir, ZipFilesystemEntry):
        assert zdir.stat().st_mode == 0o40777
