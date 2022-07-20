import pathlib
import tempfile

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers import fsutil


def test_target_path_checks_dirfs(tmpdir_name, target_win):

    with tempfile.NamedTemporaryFile(dir=tmpdir_name) as tf:
        tf.write(b"dummy")
        tf.flush()
        tmpfile_name = fsutil.basename(tf.name)

        fs = DirectoryFilesystem(path=pathlib.Path(tmpdir_name))
        target_win.filesystems.add(fs)
        target_win.fs.mount("Z:\\", fs)
        assert target_win.fs.path(f"Z:\\{tmpfile_name}").is_file()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").exists()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_mapped_dir(tmpdir_name, target_win):

    with tempfile.NamedTemporaryFile(dir=tmpdir_name) as tf:
        tf.write(b"dummy")
        tf.flush()
        tmpfile_name = fsutil.basename(tf.name)

        target_win.filesystems.entries[0].map_dir("test-dir", tmpdir_name)
        assert target_win.fs.path("C:\\test-dir\\").is_dir()
        assert not target_win.fs.path("C:\\test-dir\\").is_file()

        assert target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}").is_file()

        with pytest.raises(NotImplementedError):
            target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_virtual():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("file", VirtualFile(vfs, "file", None))
    assert not vfs.path("file/test").exists()


def test_target_path_backslash_normalisation(target_win, fs_win, tmpdir_name):

    with tempfile.NamedTemporaryFile(dir=tmpdir_name) as tf:
        tf.write(b"dummy")
        tf.flush()

        fs_win.map_dir("windows/system32/", tmpdir_name)
        fs_win.map_file("windows/system32/somefile.txt", tf.name)

        results = list(target_win.fs.path("/").glob("C:\\windows\\system32\\some*.txt"))
        assert len(results) == 1

        results = list(target_win.fs.path("/").glob("sysvol/windows/system32/some*.txt"))
        assert len(results) == 1
