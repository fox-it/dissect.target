import io
import tarfile

import pytest

from dissect.target.exceptions import IsADirectoryError, NotADirectoryError
from dissect.target.filesystems.tar import TarFilesystem, TarFilesystemEntry


def _mkdir(tf, name):
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


def _mkfile(tf, name, content):
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


def _mksym(tf, name, dest):
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


def _create_tar(prefix="", tar_dir=True, tar_sym=False):
    buf = io.BytesIO()
    tf = tarfile.TarFile(fileobj=buf, mode="w")

    if prefix and tar_dir:
        cur = []
        for p in prefix.strip("/").split("/"):
            cur.append(p)
            _mkdir(tf, "/".join(cur))

    _mkfile(tf, f"{prefix}file_1", b"file 1 contents")
    _mkfile(tf, f"{prefix}file_2", b"file 2 contents")

    if tar_dir:
        _mkdir(tf, f"{prefix}dir/")

    for i in range(100):
        _mkfile(tf, f"{prefix}dir/{i}", f"contents {i}".encode())

    if tar_sym:
        _mksym(tf, f"{prefix}sym_1", f"{prefix}file_1")
        _mksym(tf, f"{prefix}sym_2", f"{prefix}dir")

    tf.close()
    buf.seek(0)
    return buf


@pytest.fixture
def tar_simple():
    yield _create_tar()


@pytest.fixture
def tar_base():
    yield _create_tar("base/")


@pytest.fixture
def tar_relative():
    yield _create_tar("./", False)


@pytest.fixture
def tar_relative_dir():
    yield _create_tar("./")


@pytest.fixture
def tar_virtual_dir():
    yield _create_tar("", False)


@pytest.fixture
def tar_symlink():
    yield _create_tar("", tar_sym=True)


@pytest.mark.parametrize(
    "obj, base",
    [
        ("tar_simple", ""),
        ("tar_base", "base/"),
        ("tar_relative", ""),
        ("tar_relative_dir", ""),
        ("tar_virtual_dir", ""),
        ("tar_symlink", ""),
    ],
)
def test_filesystems_tar(obj, base, request):
    fh = request.getfixturevalue(obj)

    assert TarFilesystem.detect(fh)

    fs = TarFilesystem(fh, base)
    assert isinstance(fs, TarFilesystem)

    assert len(fs.listdir("/")) == (5 if fs.lexists("sym_1") else 3)

    assert fs.get("./file_1").open().read() == b"file 1 contents"
    assert fs.get("./file_2").open().read() == b"file 2 contents"
    assert len(list(fs.glob("./dir/*"))) == 100

    tfile = fs.get("./file_1")
    tdir = fs.get("./dir")

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
