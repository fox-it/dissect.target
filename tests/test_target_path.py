import os
import tempfile

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem


def test_target_path_checks_dirfs(tmp_path, target_win):
    with tempfile.NamedTemporaryFile(dir=tmp_path) as tf:
        tf.write(b"dummy")
        tf.flush()
        tmpfile_name = os.path.basename(tf.name)

        fs = DirectoryFilesystem(path=tmp_path)
        target_win.filesystems.add(fs)
        target_win.fs.mount("Z:\\", fs)
        assert target_win.fs.path(f"Z:\\{tmpfile_name}").is_file()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").exists()
        assert not target_win.fs.path(f"Z:\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_mapped_dir(tmp_path, target_win):
    with tempfile.NamedTemporaryFile(dir=tmp_path) as tf:
        tf.write(b"dummy")
        tf.flush()
        tmpfile_name = os.path.basename(tf.name)

        target_win.filesystems.entries[0].map_dir("test-dir", tmp_path)
        assert target_win.fs.path("C:\\test-dir\\").is_dir()
        assert not target_win.fs.path("C:\\test-dir\\").is_file()

        assert target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}").is_file()
        assert not target_win.fs.path(f"C:\\test-dir\\{tmpfile_name}\\some").is_file()


def test_target_path_checks_virtual():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("file", VirtualFile(vfs, "file", None))
    assert not vfs.path("file/test").exists()


def test_target_path_backslash_normalisation(target_win, fs_win, tmp_path):
    with tempfile.NamedTemporaryFile(dir=tmp_path) as tf:
        tf.write(b"dummy")
        tf.flush()

        fs_win.map_dir("windows/system32/", tmp_path)
        fs_win.map_file("windows/system32/somefile.txt", tf.name)

        results = list(target_win.fs.path("/").glob("C:\\windows\\system32\\some*.txt"))
        assert len(results) == 1

        results = list(target_win.fs.path("/").glob("sysvol/windows/system32/some*.txt"))
        assert len(results) == 1
