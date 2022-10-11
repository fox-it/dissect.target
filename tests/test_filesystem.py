import stat
from unittest.mock import Mock

import pytest

from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    SymlinkRecursionError,
)
from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.filesystems.extfs import ExtFilesystem, ExtFilesystemEntry
from dissect.target.filesystems.ffs import FfsFilesystemEntry
from dissect.target.filesystems.tar import TarFilesystemEntry
from dissect.target.filesystems.xfs import XfsFilesystemEntry

try:
    from dissect.target.filesystems.vmfs import VmfsFilesystemEntry
except ImportError:
    VmfsFilesystemEntry = None

from ._utils import absolute_path


@pytest.fixture
def vfs():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("/path/to/some/file", VirtualFile(vfs, "file", None))

    vfs.symlink("/path/to/some/", "dirlink1")
    vfs.symlink("dirlink1", "dirlink2")
    vfs.symlink("/path/to/some/file", "filelink1")
    vfs.symlink("filelink1", "filelink2")

    vfs.map_fs("/path/to/other", vfs)

    return vfs


def test_get(vfs):
    assert vfs.get("dirlink1").name == "dirlink1"
    assert vfs.get("dirlink1").is_symlink()
    assert vfs.get("dirlink1").is_dir()
    assert not vfs.get("dirlink1").is_file()
    assert vfs.get("dirlink1").listdir() == ["file"]
    assert vfs.get("dirlink1").stat() != vfs.get("dirlink1").lstat()
    assert vfs.get("dirlink1").stat() == vfs.get("/path/to/some/").stat()

    assert vfs.get("dirlink2").name == "dirlink2"
    assert vfs.get("dirlink2").is_symlink()
    assert vfs.get("dirlink2").is_dir()
    assert not vfs.get("dirlink2").is_file()
    assert vfs.get("dirlink2").listdir() == ["file"]
    assert vfs.get("dirlink2").stat() != vfs.get("dirlink2").lstat()
    assert vfs.get("dirlink2").stat() == vfs.get("/path/to/some/").stat()

    assert vfs.get("filelink1").name == "filelink1"
    assert vfs.get("filelink1").is_symlink()
    assert not vfs.get("filelink1").is_dir()
    assert vfs.get("filelink1").is_file()
    assert vfs.get("filelink1").stat() != vfs.get("filelink1").lstat()
    assert vfs.get("filelink1").stat() == vfs.get("/path/to/some/file").stat()

    assert vfs.get("filelink2").name == "filelink2"
    assert vfs.get("filelink2").is_symlink()
    assert not vfs.get("filelink2").is_dir()
    assert vfs.get("filelink2").is_file()
    assert vfs.get("filelink2").stat() != vfs.get("filelink2").lstat()
    assert vfs.get("filelink2").stat() == vfs.get("/path/to/some/file").stat()


def test_symlink_across_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    target_dir = vfs2.makedirs("/path/to/target")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = mock_target.fs.get("/path/to/symlink/target").readlink_ext()

    assert target_dir.stat() == target_entry.entries[0].stat()


def test_symlink_files_across_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    target_dir = vfs2.makedirs("/path/to/target/derp")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = mock_target.fs.get("/path/to/symlink/target/derp")

    assert len(target_entry.entries) != 0
    assert target_dir.stat() == target_entry.stat()


def test_symlink_to_symlink_across_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    target_dir = vfs1.makedirs("/path/target")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("../target", "/path/to/target")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = mock_target.fs.get("/path/to/symlink/target/").readlink_ext()

    assert target_dir.stat() == target_entry.stat()


def test_recursive_symlink_across_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("symlink/target", "/path/to/target")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    with pytest.raises(SymlinkRecursionError):
        mock_target.fs.get("/path/to/symlink/target/").readlink_ext()


def test_symlink_across_3_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("../target", "/path/to/target")

    vfs3 = VirtualFilesystem()
    target_dir = vfs3.makedirs("/path/target")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    layer3 = mock_target.fs.add_layer()
    layer3.mount("/", vfs3)

    target_entry = mock_target.fs.get("/path/to/symlink/target/").readlink_ext()

    assert target_dir.stat() == target_entry.stat()
    stat_b = mock_target.fs.get("/path/to/symlink/target/").stat()
    stat_a = mock_target.fs.get("/path/to/target/").stat()
    assert stat_a == stat_b


def test_recursive_symlink_open_across_layers(mock_target):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("symlink/target", "/path/to/target")

    layer1 = mock_target.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = mock_target.fs.add_layer()
    layer2.mount("/", vfs2)

    with pytest.raises(SymlinkRecursionError):
        mock_target.fs.get("/path/to/symlink/target/").open()


def test_recursive_symlink_dev(mock_target):
    fs1 = ExtFilesystem(fh=open(absolute_path("data/symlink_disk.ext4"), "rb"))
    mock_target.fs.mount(fs=fs1, path="/")

    with pytest.raises(SymlinkRecursionError):
        mock_target.fs.get("/path/to/symlink/target/").readlink_ext()


@pytest.mark.parametrize(
    "entry, link_dict",
    [
        (
            ExtFilesystemEntry,
            {"filetype": stat.S_IFLNK},
        ),
        (
            FfsFilesystemEntry,
            {},
        ),
        (
            VmfsFilesystemEntry,
            {},
        ),
        (
            XfsFilesystemEntry,
            {},
        ),
        (
            TarFilesystemEntry,
            {"linkname": "../target"},
        ),
    ],
)
def test_filesystem_link_resolve(entry, link_dict):
    """Test wether each filesystem resolves a link as intended."""
    if entry is None:
        pytest.skip("dissect.vmfs is required")

    mocked_link = Mock()
    mocked_file = Mock()

    for k, v in link_dict.items():
        setattr(mocked_link, k, v)

    mocked_link.is_symlink.return_value = True
    mocked_link.link = "../target"

    mocked_file.is_symlink.return_value = False
    mocked_file.issym.return_value = False

    vfs = VirtualFilesystem()

    link = entry(vfs, "path/to/symlink/target", mocked_link)
    vfs.map_file_entry(vfspath="path/to/symlink/target", entry=link)

    actual_file = entry(vfs, "path/to/target", mocked_file)
    vfs.map_file_entry(vfspath="path/to/target", entry=actual_file)

    assert link.readlink_ext() == actual_file


def test_filesystem_virtual_symlink_to_dir_get(vfs):
    some_file = vfs.get("/path/to/some/file")
    symlink = vfs.get("/dirlink1")

    some_file2 = symlink.get("file")

    assert some_file is some_file2


def test_filesystem_virtual_symlink_to_file_get(vfs):
    symlink = vfs.get("/filelink1")
    with pytest.raises(NotADirectoryError):
        symlink.get("does_not_exist")


def test_filesystem_virtual_symlink_to_symlink_get(vfs):
    some_file = vfs.get("/path/to/some/file")
    symlink = vfs.get("/dirlink2")

    some_file2 = symlink.get("file")

    assert some_file is some_file2


def test_filesystem_virtual_filesystem_get():
    vfs = VirtualFilesystem()
    file_entry = VirtualFile(vfs, "file", None)
    vfs.map_file_entry("path/to/some/file", file_entry)

    assert vfs.get("") is vfs.root
    assert vfs.get("path/to/some/file") is file_entry


@pytest.mark.parametrize(
    "vfs_path1, vfs_path2",
    [
        ("path/to/some/file", "/path/to/some/file"),
        ("path/to/some/file", "/path/to/some/file/"),
        ("path/to/some/file", "//path/to////some/file///"),
        ("path/to/some/file", "path/././to/some/./file"),
        ("path/to/some/file", "path/to/../to/some/../../../path/to/some/file"),
        ("path/to/some/file", "/dirlink1/file"),
        # as symlinks are resolved before continuing along the path, we have to
        # go back up 3 times to get back to the root
        ("path/to/some/file", "/dirlink1/../../../dirlink1/file"),
        ("path/to/some/file", "/dirlink1/../../../path/to/some/file"),
        ("path/to/some/file", "/dirlink2/file"),
        ("path/to/some/file", "/dirlink2/../../../dirlink1/file"),
        ("path/to/some/file", "/path/to/other/path/to/some/file"),
        ("path/to/some/file", "/path/to/other/dirlink1/file"),
        ("/", ""),
        ("/", "/path/to/../../"),
        ("/", "/dirlink2/../../../"),
    ],
)
def test_filesystem_virtual_filesystem_get_equal_vfs_paths(vfs, vfs_path1, vfs_path2):
    assert vfs.get(vfs_path1) is vfs.get(vfs_path2)


@pytest.mark.parametrize(
    "vfs_path1, vfs_path2",
    [
        ("path/to/some/file", "/filelink1"),
        ("path/to/some/file", "/filelink2"),
        ("/filelink1", "/filelink2"),
        ("path/to/some", "/dirlink1"),
        ("path/to/some", "/dirlink2"),
        ("/dirlink1", "/dirlink2"),
    ],
)
def test_filesystem_virtual_filesystem_get_unequal_vfs_paths(vfs, vfs_path1, vfs_path2):
    assert vfs.get(vfs_path1) is not vfs.get(vfs_path2)


@pytest.mark.parametrize(
    "vfs_path, exception",
    [
        ("/path/to/some/file/.", NotADirectoryError),
        ("/path/to/some/file/..", NotADirectoryError),
        ("/path/to/some/non-exisiting-file", FileNotFoundError),
        ("/path/to/other/path/to/some/non-exisiting-file", FileNotFoundError),
    ],
)
def test_filesystem_virtual_filesystem_get_erroring_vfs_paths(vfs, vfs_path, exception):
    with pytest.raises(exception):
        vfs.get(vfs_path)
