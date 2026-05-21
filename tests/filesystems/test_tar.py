from __future__ import annotations

import io
import tarfile
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import IsADirectoryError, NotADirectoryError
from dissect.target.filesystems.tar import TarFilesystem, TarFilesystemEntry

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


def _mkdir(tf: tarfile.TarFile, name: str) -> None:
    info = tf.tarinfo()
    info.name = name
    info.mode = 0o40777
    info.uid = 0
    info.gid = 0
    info.size = 0
    info.mtime = 3384460800
    info.type = tarfile.DIRTYPE
    info.linkname = ""
    tf.addfile(info)


def _mkfile(tf: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tf.tarinfo()
    info.name = name
    info.mode = 0o100777
    info.uid = 0
    info.gid = 0
    info.size = len(content)
    info.mtime = 3384460800
    info.type = tarfile.REGTYPE
    info.linkname = ""
    tf.addfile(info, io.BytesIO(content))


def _mksym(tf: tarfile.TarFile, name: str, dest: str) -> None:
    info = tf.tarinfo()
    info.name = name
    info.mode = 0o120777
    info.uid = 0
    info.gid = 0
    info.size = 0
    info.mtime = 3384460800
    info.type = tarfile.SYMTYPE
    info.linkname = dest
    tf.addfile(info)


def _create_tar(prefix: str = "", insert_dir: bool = True, tar_sym: bool = False) -> io.BytesIO:
    buf = io.BytesIO()
    tf = tarfile.TarFile(fileobj=buf, mode="w")

    if prefix and insert_dir:
        cur = []
        for p in (prefix.rstrip("/") if prefix != "/" else prefix).split("/"):
            cur.append(p)
            if name := "/".join(cur):
                _mkdir(tf, name)

    _mkfile(tf, f"{prefix}file_1", b"file 1 contents")
    _mkfile(tf, f"{prefix}file_2", b"file 2 contents")

    if insert_dir:
        _mkdir(tf, f"{prefix}dir/")

    for i in range(100):
        _mkfile(tf, f"{prefix}dir/{i}", f"contents {i}".encode())

    if tar_sym:
        _mksym(tf, f"{prefix}sym_1", f"{prefix}file_1")
        _mksym(tf, f"{prefix}sym_2", f"{prefix}dir")

    if insert_dir:
        _mkdir(tf, f"{prefix}LARGE/")

    for i in range(1000):
        _mkfile(tf, f"{prefix}LARGE/{i}", f"CAN. YOU. HEAR. ME. {i}".encode())

    tf.close()
    buf.seek(0)
    return buf


@pytest.fixture
def tar_simple() -> io.BytesIO:
    return _create_tar()


@pytest.fixture
def tar_base() -> io.BytesIO:
    return _create_tar("base/")


@pytest.fixture
def tar_relative() -> io.BytesIO:
    return _create_tar("./", False)


@pytest.fixture
def tar_relative_dir() -> io.BytesIO:
    return _create_tar("./")


@pytest.fixture
def tar_virtual_dir() -> io.BytesIO:
    return _create_tar("", False)


@pytest.fixture
def tar_symlink() -> io.BytesIO:
    return _create_tar("", tar_sym=True)


@pytest.fixture
def tar_absolute() -> io.BytesIO:
    return _create_tar("/", False)


@pytest.fixture
def tar_absolute_base() -> io.BytesIO:
    return _create_tar("/base/", False)


@pytest.fixture
def tar_absolute_base_dir() -> io.BytesIO:
    return _create_tar("/base/")


@pytest.mark.parametrize(
    ("obj", "base"),
    [
        pytest.param("tar_simple", None, id="simple"),
        pytest.param("tar_base", "base/", id="base"),
        pytest.param("tar_relative", None, id="relative"),
        pytest.param("tar_relative_dir", None, id="relative-dir"),
        pytest.param("tar_virtual_dir", None, id="virtual-dir"),
        pytest.param("tar_symlink", None, id="symlink"),
        pytest.param("tar_absolute", None, id="absolute"),
        pytest.param("tar_absolute_base", "/base/", id="absolute-base"),
        pytest.param("tar_absolute_base_dir", "/base/", id="absolute-base-dir"),
    ],
)
def test_tar(obj: str, base: str | None, request: pytest.FixtureRequest) -> None:
    fh = request.getfixturevalue(obj)

    assert TarFilesystem.detect(fh)

    fs = TarFilesystem(fh, base)
    assert isinstance(fs, TarFilesystem)

    assert len(fs.listdir("/")) == (6 if fs.lexists("sym_1") else 4)

    assert fs.get("file_1").open().read() == b"file 1 contents"
    assert fs.get("file_2").open().read() == b"file 2 contents"
    assert len(list(fs.glob("dir/*"))) == 100

    tfile = fs.get("file_1")
    tdir = fs.get("dir")

    assert tfile.is_file()
    assert not tfile.is_dir()
    assert not tfile.is_symlink()

    with pytest.raises(NotADirectoryError):
        tfile.listdir()

    assert tdir.is_dir()
    assert not tdir.is_file()
    assert not tdir.is_symlink()

    with pytest.raises(IsADirectoryError):
        tdir.open()

    file1 = tdir.get("1")
    assert file1.is_file()
    assert not file1.is_dir()
    assert not file1.is_symlink()
    assert file1.open().read() == b"contents 1"

    assert tfile.stat().st_mode == 0o100777

    if isinstance(tdir, TarFilesystemEntry):
        assert tdir.stat().st_mode == 0o40777

    if fs.lexists("sym_1"):
        tsymf = fs.get("sym_1")

        assert tsymf.is_file()
        assert not tsymf.is_file(follow_symlinks=False)
        assert not tsymf.is_dir()
        assert tsymf.is_symlink()

        assert tsymf.lstat().st_mode == 0o120777
        assert tsymf.stat().st_mode == 0o100777
        assert tsymf.stat(follow_symlinks=False) == tsymf.lstat()

        with pytest.raises(NotADirectoryError):
            tsymf.listdir()

        assert tsymf.open().read() == b"file 1 contents"

    if fs.lexists("sym_2"):
        tsymd = fs.get("sym_2")

        assert not tsymd.is_file()
        assert tsymd.is_dir()
        assert not tsymd.is_dir(follow_symlinks=False)
        assert tsymd.is_symlink()

        assert tsymd.lstat().st_mode == 0o120777
        assert tsymd.stat().st_mode == 0o40777
        assert tsymd.stat(follow_symlinks=False) == tsymd.lstat()

        with pytest.raises(IsADirectoryError):
            tsymd.open()

        assert len(list(tsymd.listdir())) == 100


def test_tar_case_sensitivity(tar_simple: io.BytesIO) -> None:
    fs = TarFilesystem(tar_simple)
    with pytest.raises(FileNotFoundError):
        fs.get("FILE_1")

    assert fs.get("LARGE/1").open().read() == b"CAN. YOU. HEAR. ME. 1"

    fs = TarFilesystem(tar_simple, case_sensitive=False)
    assert fs.get("FILE_1").open().read() == b"file 1 contents"
    assert fs.get("large/1").open().read() == b"CAN. YOU. HEAR. ME. 1"


@pytest.mark.parametrize(
    ("obj", "base"),
    [
        pytest.param("tar_simple", None, id="simple"),
        pytest.param("tar_base", "base/", id="base"),
        pytest.param("tar_relative", None, id="relative"),
        pytest.param("tar_relative_dir", None, id="relative-dir"),
        pytest.param("tar_virtual_dir", None, id="virtual-dir"),
        pytest.param("tar_absolute", None, id="absolute"),
        pytest.param("tar_absolute_base", "/base/", id="absolute-base"),
        pytest.param("tar_absolute_base_dir", "/base/", id="absolute-base-virtual-dir"),
    ],
)
@pytest.mark.benchmark
def test_benchmark_tar_filesystem(
    obj: str, base: str | None, request: pytest.FixtureRequest, benchmark: BenchmarkFixture
) -> None:
    fh = request.getfixturevalue(obj)

    def benchy() -> None:
        fs = TarFilesystem(fh, base)
        fs.listdir("/")
        list(fs.scandir("/"))
        fs.get("file_1").open().read()
        fs.get("dir").listdir()
        list(fs.get("dir").scandir())
        fs.get("LARGE").listdir()
        list(fs.get("LARGE").scandir())

    benchmark(benchy)
