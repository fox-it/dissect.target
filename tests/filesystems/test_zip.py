from __future__ import annotations

import io
import zipfile
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import (
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystems.zip import ZipFilesystem

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


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


def _create_zip(prefix: str = "", insert_dir: bool = True) -> io.BytesIO:
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")

    if prefix and insert_dir:
        cur = []
        for p in (prefix.rstrip("/") if prefix != "/" else prefix).split("/"):
            cur.append(p)
            if name := "/".join(cur):
                _mkdir(zf, name)

    zf.writestr(zipfile.ZipInfo(f"{prefix}file_1", (1980, 0, 0, 0, 0, 0)), "file 1 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_2", (2107, 1, 1, 0, 0, 0)), "file 2 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_3", (1980, 1, 0, 0, 0, 0)), "file 3 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_4", (2107, 13, 1, 0, 0, 0)), "file 4 contents")
    zf.writestr(zipfile.ZipInfo(f"{prefix}file_5", (2025, 9, 8, 10, 39, 40)), "file 5 contents")

    if insert_dir:
        _mkdir(zf, f"{prefix}dir/")

    for i in range(100):
        zf.writestr(f"{prefix}dir/{i}", f"contents {i}")

    symlink = zipfile.ZipInfo(f"{prefix}symlink_dir")
    symlink.external_attr = 0o120777 << 16
    zf.writestr(symlink, "dir/")

    symlink = zipfile.ZipInfo(f"{prefix}symlink_file")
    symlink.external_attr = 0o120777 << 16
    zf.writestr(symlink, "file_1")

    if insert_dir:
        _mkdir(zf, f"{prefix}LARGE/")

    for i in range(1000):
        zf.writestr(f"{prefix}LARGE/{i}", f"CAN. YOU. HEAR. ME. {i}")

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


@pytest.fixture
def zip_absolute() -> io.BytesIO:
    return _create_zip("/", False)


@pytest.fixture
def zip_absolute_base() -> io.BytesIO:
    return _create_zip("/base/")


@pytest.fixture
def zip_absolute_base_dir() -> io.BytesIO:
    return _create_zip("/base/", False)


@pytest.mark.parametrize(
    ("obj", "base"),
    [
        pytest.param("zip_simple", None, id="simple"),
        pytest.param("zip_base", "base/", id="base"),
        pytest.param("zip_relative", None, id="relative"),
        pytest.param("zip_relative_dir", None, id="relative-dir"),
        pytest.param("zip_virtual_dir", None, id="virtual-dir"),
        pytest.param("zip_absolute", None, id="absolute"),
        pytest.param("zip_absolute_base", "/base/", id="absolute-base"),
        pytest.param("zip_absolute_base_dir", "/base/", id="absolute-base-dir"),
    ],
)
def test_zip(obj: str, base: str | None, request: pytest.FixtureRequest) -> None:
    fh = request.getfixturevalue(obj)

    assert ZipFilesystem.detect(fh)

    fs = ZipFilesystem(fh, base)
    assert isinstance(fs, ZipFilesystem)
    assert len(fs.listdir("/")) == 9

    assert fs.get("file_1").open().read() == b"file 1 contents"
    assert fs.get("file_2").open().read() == b"file 2 contents"
    assert fs.get("file_3").open().read() == b"file 3 contents"
    assert fs.get("file_1").lstat().st_mtime_ns == 315532800000000000
    assert fs.get("file_2").lstat().st_mtime_ns == 4323283200000000000
    assert fs.get("file_3").lstat().st_mtime_ns == 315532800000000000
    assert fs.get("file_4").lstat().st_mtime_ns == 4354819199000000000
    assert fs.get("file_5").lstat().st_mtime_ns == 1757327980000000000
    assert fs.get("symlink_file").open().read() == b"file 1 contents"
    assert len(list(fs.glob("dir/*"))) == 100
    assert len(list(fs.glob("symlink_dir/*"))) == 100

    zfile = fs.get("file_1")
    zdir = fs.get("dir")
    zsymd = fs.get("symlink_dir")
    zsymf = fs.get("symlink_file")

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

    assert file1.stat() == zsymd.readlink_ext().get("1").stat()

    assert zfile.stat().st_mode == 0o100600
    assert zfile.stat(follow_symlinks=False) == zfile.lstat()


def test_zip_case_sensitivity(zip_simple: io.BytesIO) -> None:
    fs = ZipFilesystem(zip_simple, case_sensitive=True)
    with pytest.raises(FileNotFoundError):
        fs.get("FILE_1")

    assert fs.get("LARGE/1").open().read() == b"CAN. YOU. HEAR. ME. 1"

    fs = ZipFilesystem(zip_simple, case_sensitive=False)
    assert fs.get("FILE_1").open().read() == b"file 1 contents"
    assert fs.get("large/1").open().read() == b"CAN. YOU. HEAR. ME. 1"


@pytest.mark.parametrize(
    ("obj", "base"),
    [
        pytest.param("zip_simple", None, id="simple"),
        pytest.param("zip_base", "base/", id="base"),
        pytest.param("zip_relative", None, id="relative"),
        pytest.param("zip_relative_dir", None, id="relative-dir"),
        pytest.param("zip_virtual_dir", None, id="virtual-dir"),
        pytest.param("zip_absolute", None, id="absolute"),
        pytest.param("zip_absolute_base", "/base/", id="absolute-base"),
        pytest.param("zip_absolute_base_dir", "/base/", id="absolute-base-dir"),
    ],
)
@pytest.mark.benchmark
def test_benchmark_zip_filesystem(
    obj: str, base: str | None, request: pytest.FixtureRequest, benchmark: BenchmarkFixture
) -> None:
    fh = request.getfixturevalue(obj)

    def benchy() -> None:
        fs = ZipFilesystem(fh, base)
        fs.listdir("/")
        list(fs.scandir("/"))
        fs.get("file_1").open().read()
        fs.get("dir").listdir()
        list(fs.get("dir").scandir())
        fs.get("LARGE").listdir()
        list(fs.get("LARGE").scandir())

    benchmark(benchy)


def test_skip_folder_member_if_previously_mapped() -> None:
    """Test if we skip a directory zip member if the path of said directory is already mapped."""
    buf = io.BytesIO()
    zf = zipfile.ZipFile(file=buf, mode="w")
    zf.writestr("folder/file", b"file contents")  # write the file member first
    _mkdir(zf, "folder")  # then write the 'empty' dir member
    zf.close()
    buf.seek(0)
    fs = ZipFilesystem(buf)

    # Sanity check
    assert list(fs.get("/").iterdir()) == ["folder"]

    # Make sure the /folder/file entry is mapped.
    assert list(fs.get("/folder").iterdir()) == ["file"]
    assert fs.get("/folder/file").open().read() == b"file contents"
