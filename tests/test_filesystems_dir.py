import pathlib
import tempfile

from dissect.target.filesystems.dir import DirectoryFilesystem


def test_filesystem_dir_symlink_to_file(tmp_path):
    with tempfile.NamedTemporaryFile(dir=tmp_path) as tf:
        tf.write(b"dummy")
        tf.flush()

        tmpfile_path = pathlib.Path(tf.name)
        symlink_path = tmp_path.joinpath("symlink")
        symlink_path.symlink_to(f"/{tmpfile_path.name}")

        fs = DirectoryFilesystem(path=tmp_path)
        symlink_entry = fs.get("symlink")

        assert symlink_entry.is_symlink()
        assert symlink_entry.is_file()
        assert not symlink_entry.is_dir()
        assert symlink_entry.exists()

        assert symlink_entry.readlink() == f"/{tmpfile_path.name}"
        assert symlink_entry.readlink_ext().entry == fs.get(tmpfile_path.name).entry

        assert symlink_entry.open().read() == fs.get(tmpfile_path.name).open().read() == b"dummy"

        assert list(symlink_entry.lstat()) == list(symlink_path.lstat())
        assert list(symlink_entry.stat()) == list(tmpfile_path.lstat())


def test_filesystem_dir_symlink_to_dir(tmp_path):
    nested_path = tmp_path.joinpath("nested")
    nested_path.mkdir()
    nested_path.joinpath("file1").touch()
    nested_path.joinpath("file2").touch()

    symlink_path = tmp_path.joinpath("symlink")
    symlink_path.symlink_to("/nested")

    fs = DirectoryFilesystem(path=tmp_path)
    symlink_entry = fs.get("symlink")

    assert symlink_entry.is_symlink()
    assert not symlink_entry.is_file()
    assert symlink_entry.is_dir()
    assert symlink_entry.exists()

    assert symlink_entry.readlink() == "/nested"
    assert symlink_entry.readlink_ext().entry == fs.get("/nested").entry

    assert sorted(list(symlink_entry.iterdir())) == ["file1", "file2"]
    assert sorted([e.entry for e in symlink_entry.scandir()], key=lambda e: e.name) == [
        fs.get("/nested/file1").entry,
        fs.get("/nested/file2").entry,
    ]
