import os
import stat
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import Mock

import pytest

from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    SymlinkRecursionError,
)
from dissect.target.filesystem import (
    MappedFile,
    RootFilesystem,
    RootFilesystemEntry,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
    VirtualSymlink,
)
from dissect.target.filesystems.extfs import ExtFilesystem, ExtFilesystemEntry
from dissect.target.filesystems.ffs import FfsFilesystemEntry
from dissect.target.filesystems.tar import TarFilesystemEntry
from dissect.target.filesystems.xfs import XfsFilesystemEntry

try:
    from dissect.target.filesystems.vmfs import VmfsFilesystemEntry
except ImportError:
    VmfsFilesystemEntry = None

from dissect.target.helpers import fsutil

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


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/",
    ],
)
@pytest.mark.parametrize(
    "entry_name",
    [
        "/path/to/some/file",
        "/path/to/some",
        "/dirlink1",
    ],
)
def test_filesystem_virtual_entry_get_self(vfs, path, entry_name):
    some_entry = vfs.get(entry_name)
    some_entry2 = some_entry.get(path)

    assert some_entry is some_entry2


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


def test_filesystem_vritual_filesystem_get_case_sensitive():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("/path/to/some/file_lower_case", VirtualFile(vfs, "file_lower_case", None))
    vfs.map_file_entry("/path/TO/some/FILE_UPPER_CASE", VirtualFile(vfs, "FILE_UPPER_CASE", None))

    assert vfs.get("/path/to/some/file_lower_case").name == "file_lower_case"
    assert vfs.get("/path/TO/some/FILE_UPPER_CASE").name == "FILE_UPPER_CASE"
    with pytest.raises(FileNotFoundError):
        vfs.get("/path/to/some/FILE_LOWER_CASE")
    with pytest.raises(FileNotFoundError):
        assert vfs.get("/path/TO/some/file_upper_case")


def test_filesystem_vritual_filesystem_get_case_insensitive():
    vfs = VirtualFilesystem(case_sensitive=False)
    vfs.map_file_entry("/path/to/some/file_lower_case", VirtualFile(vfs, "file_lower_case", None))
    vfs.map_file_entry("/path/TO/some/FILE_UPPER_CASE", VirtualFile(vfs, "FILE_UPPER_CASE", None))

    assert vfs.get("/path/to/some/file_lower_case").name == "file_lower_case"
    assert vfs.get("/path/TO/some/FILE_UPPER_CASE").name == "FILE_UPPER_CASE"
    assert vfs.get("/path/to/some/FILE_LOWER_CASE").name == "file_lower_case"
    assert vfs.get("/path/TO/some/file_upper_case").name == "FILE_UPPER_CASE"


@pytest.mark.parametrize(
    "paths",
    [
        ("/some/dir",),
        ("some/dir/",),
        ("/some/dir/",),
        ("some/dir",),
        (
            "/some/dir/",
            "some/dir/other/dir",
        ),
    ],
)
def test_filesystem_virtual_filesystem_makedirs(paths):
    vfs = VirtualFilesystem()

    for vfspath in paths:
        vfs.makedirs(vfspath)

        partial_path = ""
        for part in vfspath.strip("/").split("/"):
            partial_path = fsutil.join(partial_path, part, alt_separator=vfs.alt_separator)
            vfs_entry = vfs.get(partial_path)

            assert isinstance(vfs_entry, VirtualDirectory)
            assert vfs_entry.path == partial_path.strip("/")


def test_filesystem_virtual_filesystem_makedirs_root():
    vfs = VirtualFilesystem()
    vfspath = "/"

    vfs.makedirs(vfspath)

    vfs_entry = vfs.get(vfspath)

    assert vfs_entry is vfs.root


def test_filesystem_virtual_filesystem_map_fs(vfs):
    root_vfs = VirtualFilesystem()
    map_path = "/some/dir/"
    file_path = "/path/to/some/file"
    root_file_path = fsutil.join(map_path, file_path, alt_separator=vfs.alt_separator)

    root_vfs.map_fs(map_path, vfs)

    vfs_entry = vfs.get(file_path)
    root_vfs_entry = vfs.get(root_file_path)

    assert vfs_entry is root_vfs_entry

    with pytest.raises(FileNotFoundError):
        root_vfs.get(file_path)


def test_filesystem_virtual_filesystem_mount(vfs):
    assert vfs.mount == vfs.map_fs


def test_filesystem_virtual_filesystem_map_dir():
    vfs = VirtualFilesystem()
    vfs_path = "/map/point/"
    with TemporaryDirectory() as tmp_dir:
        with TemporaryDirectory(dir=tmp_dir) as some_dir:
            with TemporaryDirectory(dir=tmp_dir) as other_dir:
                with TemporaryDirectory(dir=other_dir) as second_lvl_dir:
                    with NamedTemporaryFile(dir=some_dir) as some_file:
                        some_file.write(b"1337")
                        some_file.seek(0)

                        vfs.map_dir(vfs_path, tmp_dir)

                        rel_path = os.path.relpath(some_dir, tmp_dir)
                        rel_path = fsutil.normalize(rel_path, alt_separator=os.path.sep)
                        entry_name = fsutil.join(vfs_path, rel_path, alt_separator=vfs.alt_separator)
                        dir_entry = vfs.get(entry_name)
                        assert isinstance(dir_entry, VirtualDirectory)

                        rel_path = os.path.relpath(second_lvl_dir, tmp_dir)
                        rel_path = fsutil.normalize(rel_path, alt_separator=os.path.sep)
                        entry_name = fsutil.join(vfs_path, rel_path, alt_separator=vfs.alt_separator)
                        dir_entry = vfs.get(entry_name)
                        assert isinstance(dir_entry, VirtualDirectory)

                        rel_path = os.path.relpath(some_file.name, tmp_dir)
                        rel_path = fsutil.normalize(rel_path, alt_separator=os.path.sep)
                        entry_name = fsutil.join(vfs_path, rel_path, alt_separator=vfs.alt_separator)
                        file_entry = vfs.get(entry_name)
                        assert isinstance(file_entry, MappedFile)

                        fp = file_entry.open()
                        assert fp.read() == b"1337"


@pytest.mark.parametrize(
    "vfs_path",
    [
        "/path/to/file",
        "path/to/file",
        "/path///to/file",
    ],
)
def test_filesystem_virtual_filesystem_map_file(vfs_path):
    vfs = VirtualFilesystem()
    real_path = "/tmp/foo"

    vfs.map_file(vfs_path, real_path)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    vfs_entry = vfs.get(vfs_path)

    assert isinstance(vfs_entry, MappedFile)
    assert vfs_entry.path == vfs_path
    assert vfs_entry.entry == real_path


def test_filesystem_virtual_filesystem_map_file_as_dir():
    vfs = VirtualFilesystem()
    real_path = "/tmp/foo"

    with pytest.raises(AttributeError):
        vfs.map_file("/path/to/dir/", real_path)


@pytest.mark.parametrize(
    "vfs_path",
    [
        "/path/to/file",
        "path/to/file",
        "/path///to/file",
    ],
)
def test_filesystem_virtual_filesystem_map_file_fh(vfs_path):
    vfs = VirtualFilesystem()
    fh = Mock()

    vfs.map_file_fh(vfs_path, fh)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    vfs_entry = vfs.get(vfs_path)

    assert isinstance(vfs_entry, VirtualFile)
    assert vfs_entry.path == vfs_path
    assert vfs_entry.entry is fh


def test_filesystem_virtual_filesystem_map_file_fh_as_dir():
    vfs = VirtualFilesystem()
    fh = Mock()

    with pytest.raises(AttributeError):
        vfs.map_file_fh("/path/to/dir/", fh)


@pytest.mark.parametrize(
    "vfs_path",
    [
        "/path/to/entry",
        "path/to/entry",
        "path/to/entry/",
        "/path/to/entry/",
        "//path///to/entry//",
        "/entry",
        "entry",
        "entry/",
        "/entry/",
        "/",
    ],
)
def test_filesystem_virtual_filesystem_map_file_entry(vfs_path):
    vfs = VirtualFilesystem()
    entry_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    dir_entry = VirtualDirectory(vfs, entry_path)

    file_name = fsutil.join(vfs_path, "test", alt_separator=vfs.alt_separator)
    file_entry = VirtualFile(vfs, file_name, Mock())
    dir_entry.add("test", file_entry)

    vfs.map_file_entry(vfs_path, dir_entry)

    vfs_entry = vfs.get(vfs_path)

    if vfs_path == "/":
        assert vfs.get(file_name) is file_entry
    else:
        assert vfs_entry is dir_entry


@pytest.mark.parametrize(
    "vfs_path, link_path",
    [
        (
            "/path/to/entry",
            "/path/to/link",
        ),
        (
            "path/to/entry",
            "path/to/link",
        ),
        (
            "path/to/entry/",
            "path/to/link/",
        ),
        (
            "/path/to/entry/",
            "/path/to/link/",
        ),
        (
            "//path///to/entry//",
            "//path///to/link//",
        ),
    ],
)
def test_filesystem_virtual_filesystem_link(vfs_path, link_path):
    vfs = VirtualFilesystem()
    entry_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    file_object = Mock()
    file_entry = VirtualFile(vfs, entry_path, file_object)
    vfs.map_file_entry(vfs_path, file_entry)

    vfs.link(vfs_path, link_path)

    link_path = fsutil.normalize(link_path, alt_separator=vfs.alt_separator).strip("/")
    link_entry = vfs.get(link_path)

    assert link_entry is file_entry


@pytest.mark.parametrize(
    "vfs_path, link_path",
    [
        (
            "/path/to/entry",
            "/path/to/link",
        ),
        (
            "path/to/entry",
            "path/to/link",
        ),
        (
            "path/to/entry/",
            "path/to/link/",
        ),
        (
            "/path/to/entry/",
            "/path/to/link/",
        ),
        (
            "//path///to/entry//",
            "//path///to/link//",
        ),
    ],
)
def test_filesystem_virtual_filesystem_symlink(vfs_path, link_path):
    vfs = VirtualFilesystem()

    vfs.symlink(vfs_path, link_path)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    link_path = fsutil.normalize(link_path, alt_separator=vfs.alt_separator).strip("/")
    link_entry = vfs.get(link_path)

    assert isinstance(link_entry, VirtualSymlink)
    assert link_entry.path == link_path
    assert link_entry.target == vfs_path


def test_filesystem_root_filesystem_get():
    vfs1 = VirtualFilesystem()

    vfs1_entry = VirtualFile(vfs1, "vfs1_entry", Mock())
    vfs1.map_file_entry("/vfs1_entry", vfs1_entry)

    vfs1.symlink("/vfs1/vfs2/", "/link_to_vfs2")
    vfs1_link = vfs1.get("/link_to_vfs2")

    vfs2 = VirtualFilesystem()

    vfs2_entry = VirtualFile(vfs2, "vfs2_entry", Mock())
    vfs2.map_file_entry("/vfs2_entry", vfs2_entry)

    vfs2_shared_entry = VirtualFile(vfs2, "shared_entry", Mock())
    vfs2.map_file_entry("/shared_entry", vfs2_shared_entry)

    target = Mock()
    rootfs = RootFilesystem(target)
    rootfs.mount("/vfs1", vfs1)
    rootfs.mount("/vfs1/vfs2", vfs2)

    entry_path = "/vfs1/vfs1_entry"
    rootfs_entry = rootfs.get(entry_path)
    assert rootfs_entry.path == entry_path
    assert len(rootfs_entry.entries) == 1
    assert vfs1_entry in rootfs_entry.entries

    entry_path = "/vfs1/vfs2/vfs2_entry"
    rootfs_entry = rootfs.get(entry_path)
    assert rootfs_entry.path == entry_path
    assert len(rootfs_entry.entries) == 1
    assert vfs2_entry in rootfs_entry.entries

    entry_path = "/vfs1"
    rootfs_entry = rootfs.get(entry_path)
    assert rootfs_entry.path == entry_path
    assert len(rootfs_entry.entries) == 2
    assert isinstance(rootfs_entry.entries[0], VirtualDirectory)
    assert isinstance(rootfs_entry.entries[1], VirtualDirectory)

    entry_path = "/vfs1/link_to_vfs2"
    rootfs_entry = rootfs.get(entry_path)
    assert rootfs_entry.path == entry_path
    assert len(rootfs_entry.entries) == 1
    assert vfs1_link in rootfs_entry.entries

    entry_path = "/vfs1/link_to_vfs2/vfs2_entry"
    rootfs_entry = rootfs.get(entry_path)
    assert rootfs_entry.path == entry_path
    assert len(rootfs_entry.entries) == 1
    nested_rootfs_entry = rootfs_entry.entries[0]
    assert isinstance(nested_rootfs_entry, RootFilesystemEntry)
    assert len(nested_rootfs_entry.entries) == 1
    assert vfs2_entry in nested_rootfs_entry.entries
