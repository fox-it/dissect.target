import os
import stat
from io import BytesIO
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Union
from unittest.mock import Mock, patch

import pytest
from _pytest.fixtures import FixtureRequest

from dissect.target import filesystem
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
from tests._utils import absolute_path


@pytest.fixture
def vfs():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("/path/to/some/file", VirtualFile(vfs, "path/to/some/file", None))

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


def test_symlink_across_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    target_dir = vfs2.makedirs("/path/to/target")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = target_bare.fs.get("/path/to/symlink/target").readlink_ext()

    assert target_dir.stat() == target_entry.entries[0].stat()


def test_symlink_files_across_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    target_dir = vfs2.makedirs("/path/to/target/derp")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = target_bare.fs.get("/path/to/symlink/target/derp")

    assert len(target_entry.entries) != 0
    assert target_dir.stat() == target_entry.stat()


def test_symlink_to_symlink_across_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    target_dir = vfs1.makedirs("/path/target")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("../target", "/path/to/target")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    target_entry = target_bare.fs.get("/path/to/symlink/target/").readlink_ext()

    assert target_dir.stat() == target_entry.stat()


def test_recursive_symlink_across_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("symlink/target", "/path/to/target")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    with pytest.raises(SymlinkRecursionError):
        target_bare.fs.get("/path/to/symlink/target/").readlink_ext()


def test_symlink_across_3_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("../target", "/path/to/target")

    vfs3 = VirtualFilesystem()
    target_dir = vfs3.makedirs("/path/target")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    layer3 = target_bare.fs.add_layer()
    layer3.mount("/", vfs3)

    target_entry = target_bare.fs.get("/path/to/symlink/target/").readlink_ext()

    assert target_dir.stat() == target_entry.stat()
    stat_b = target_bare.fs.get("/path/to/symlink/target/").stat()
    stat_a = target_bare.fs.get("/path/to/target/").stat()
    assert stat_a == stat_b


def test_recursive_symlink_open_across_layers(target_bare):
    vfs1 = VirtualFilesystem()
    vfs1.makedirs("/path/to/symlink/")
    vfs1.symlink("../target", "/path/to/symlink/target")

    vfs2 = VirtualFilesystem()
    vfs2.symlink("symlink/target", "/path/to/target")

    layer1 = target_bare.fs.add_layer()
    layer1.mount("/", vfs1)

    layer2 = target_bare.fs.add_layer()
    layer2.mount("/", vfs2)

    with pytest.raises(SymlinkRecursionError):
        target_bare.fs.get("/path/to/symlink/target/").open()


def test_recursive_symlink_dev(target_bare):
    fs1 = ExtFilesystem(fh=open(absolute_path("_data/filesystem/symlink_disk.ext4"), "rb"))
    target_bare.fs.mount(fs=fs1, path="/")

    with pytest.raises(SymlinkRecursionError):
        target_bare.fs.get("/path/to/symlink/target/").readlink_ext()


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
def test_link_resolve(entry, link_dict):
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


def test_virtual_symlink_to_dir_get(vfs):
    some_file = vfs.get("/path/to/some/file")
    symlink = vfs.get("/dirlink1")

    some_file2 = symlink.get("file")

    assert some_file is some_file2


def test_virtual_symlink_to_file_get(vfs):
    symlink = vfs.get("/filelink1")
    with pytest.raises(NotADirectoryError):
        symlink.get("does_not_exist")


def test_virtual_symlink_to_symlink_get(vfs):
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
def test_virtual_entry_get_self(vfs, path, entry_name):
    some_entry = vfs.get(entry_name)
    some_entry2 = some_entry.get(path)

    assert some_entry is some_entry2


def test_virtual_filesystem_get():
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
def test_virtual_filesystem_get_equal_vfs_paths(vfs, vfs_path1, vfs_path2):
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
def test_virtual_filesystem_get_unequal_vfs_paths(vfs, vfs_path1, vfs_path2):
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
def test_virtual_filesystem_get_erroring_vfs_paths(vfs, vfs_path, exception):
    with pytest.raises(exception):
        vfs.get(vfs_path)


def test_virtual_filesystem_get_case_sensitive():
    vfs = VirtualFilesystem()
    vfs.map_file_entry("/path/to/some/file_lower_case", VirtualFile(vfs, "file_lower_case", None))
    vfs.map_file_entry("/path/TO/some/FILE_UPPER_CASE", VirtualFile(vfs, "FILE_UPPER_CASE", None))

    assert vfs.get("/path/to/some/file_lower_case").name == "file_lower_case"
    assert vfs.get("/path/TO/some/FILE_UPPER_CASE").name == "FILE_UPPER_CASE"
    with pytest.raises(FileNotFoundError):
        vfs.get("/path/to/some/FILE_LOWER_CASE")
    with pytest.raises(FileNotFoundError):
        assert vfs.get("/path/TO/some/file_upper_case")


def test_virtual_filesystem_get_case_insensitive():
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
def test_virtual_filesystem_makedirs(paths):
    vfs = VirtualFilesystem()

    for vfspath in paths:
        vfs.makedirs(vfspath)

        partial_path = ""
        for part in vfspath.strip("/").split("/"):
            partial_path = fsutil.join(partial_path, part, alt_separator=vfs.alt_separator)
            vfs_entry = vfs.get(partial_path)

            assert isinstance(vfs_entry, VirtualDirectory)
            assert vfs_entry.path == partial_path.strip("/")


def test_virtual_filesystem_makedirs_root():
    vfs = VirtualFilesystem()
    vfspath = "/"

    vfs.makedirs(vfspath)

    vfs_entry = vfs.get(vfspath)

    assert vfs_entry is vfs.root


def test_virtual_filesystem_map_fs(vfs):
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


def test_virtual_filesystem_mount(vfs):
    assert vfs.mount == vfs.map_fs


def test_virtual_filesystem_map_dir():
    vfs = VirtualFilesystem()
    vfs_path = "/map/point/"
    with (
        TemporaryDirectory() as tmp_dir,
        TemporaryDirectory(dir=tmp_dir) as some_dir,
        TemporaryDirectory(dir=tmp_dir) as other_dir,
        TemporaryDirectory(dir=other_dir) as second_lvl_dir,
        NamedTemporaryFile(dir=some_dir, delete=False) as some_file,
    ):
        some_file.write(b"1337")
        some_file.close()

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
        fp.close()


@pytest.mark.parametrize(
    "vfs_path",
    [
        "/path/to/file",
        "path/to/file",
        "/path///to/file",
    ],
)
def test_virtual_filesystem_map_file(vfs_path):
    vfs = VirtualFilesystem()
    real_path = "/tmp/foo"

    vfs.map_file(vfs_path, real_path)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    vfs_entry = vfs.get(vfs_path)

    assert isinstance(vfs_entry, MappedFile)
    assert vfs_entry.path == vfs_path
    assert vfs_entry.entry == real_path


def test_virtual_filesystem_map_file_as_dir():
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
def test_virtual_filesystem_map_file_fh(vfs_path):
    vfs = VirtualFilesystem()
    fh = Mock()

    vfs.map_file_fh(vfs_path, fh)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    vfs_entry = vfs.get(vfs_path)

    assert isinstance(vfs_entry, VirtualFile)
    assert vfs_entry.path == vfs_path
    assert vfs_entry.entry is fh


def test_virtual_filesystem_map_file_fh_as_dir():
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
def test_virtual_filesystem_map_file_entry(vfs_path):
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
def test_virtual_filesystem_link(vfs_path, link_path):
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
def test_virtual_filesystem_symlink(vfs_path, link_path):
    vfs = VirtualFilesystem()

    vfs.symlink(vfs_path, link_path)

    vfs_path = fsutil.normalize(vfs_path, alt_separator=vfs.alt_separator).strip("/")
    link_path = fsutil.normalize(link_path, alt_separator=vfs.alt_separator).strip("/")
    link_entry = vfs.get(link_path)

    assert isinstance(link_entry, VirtualSymlink)
    assert link_entry.path == link_path
    assert link_entry.target == vfs_path


@pytest.fixture
def dir_entry(vfs: VirtualFilesystem) -> VirtualDirectory:
    return vfs.get("/path/to/some")


@pytest.fixture
def dirlink_entry(vfs: VirtualFilesystem) -> VirtualSymlink:
    return vfs.get("dirlink1")


@pytest.fixture
def file_entry(vfs: VirtualFilesystem) -> VirtualFile:
    return vfs.get("/path/to/some/file")


@pytest.fixture
def filelink_entry(vfs: VirtualFilesystem) -> VirtualSymlink:
    return vfs.get("filelink1")


@pytest.mark.parametrize(
    "src_entry, dst_entry",
    [
        ("dir_entry", "dir_entry"),
        ("dirlink_entry", "dir_entry"),
        ("file_entry", "file_entry"),
        ("filelink_entry", "file_entry"),
    ],
)
def test_virtual_filesystem_stat(
    vfs: VirtualFilesystem,
    src_entry: str,
    dst_entry: str,
    request: FixtureRequest,
) -> None:
    src_entry = request.getfixturevalue(src_entry)
    dst_entry = request.getfixturevalue(dst_entry)

    assert vfs.stat(src_entry.path, follow_symlinks=False) == src_entry.stat(follow_symlinks=False)
    assert vfs.stat(src_entry.path, follow_symlinks=True) == dst_entry.stat(follow_symlinks=True)


@pytest.mark.parametrize(
    "entry",
    [
        "dir_entry",
        "dirlink_entry",
        "file_entry",
        "filelink_entry",
    ],
)
def test_virtual_filesystem_lstat(vfs: VirtualFilesystem, entry: str, request: FixtureRequest) -> None:
    entry = request.getfixturevalue(entry)

    assert vfs.lstat(entry.path) == entry.lstat()
    assert vfs.stat(entry.path, follow_symlinks=False) == entry.lstat()


@pytest.mark.parametrize(
    "src_entry, dst_entry",
    [
        ("dir_entry", "dir_entry"),
        ("dirlink_entry", "dir_entry"),
        ("file_entry", "file_entry"),
        ("filelink_entry", "file_entry"),
    ],
)
def test_virtual_filesystem_is_dir(
    vfs: VirtualFilesystem,
    src_entry: str,
    dst_entry: str,
    request: FixtureRequest,
) -> None:
    src_entry = request.getfixturevalue(src_entry)
    dst_entry = request.getfixturevalue(dst_entry)

    assert vfs.is_dir(src_entry.path, follow_symlinks=False) == src_entry.is_dir(follow_symlinks=False)
    assert vfs.is_dir(src_entry.path, follow_symlinks=True) == src_entry.is_dir(follow_symlinks=True)
    assert vfs.is_dir(src_entry.path, follow_symlinks=True) == dst_entry.is_dir(follow_symlinks=False)
    assert vfs.is_dir(src_entry.path, follow_symlinks=True) == dst_entry.is_dir(follow_symlinks=True)


@pytest.mark.parametrize(
    "src_entry, dst_entry",
    [
        ("dir_entry", "dir_entry"),
        ("dirlink_entry", "dir_entry"),
        ("file_entry", "file_entry"),
        ("filelink_entry", "file_entry"),
    ],
)
def test_virtual_filesystem_is_file(
    vfs: VirtualFilesystem,
    src_entry: str,
    dst_entry: str,
    request: FixtureRequest,
) -> None:
    src_entry = request.getfixturevalue(src_entry)
    dst_entry = request.getfixturevalue(dst_entry)

    assert vfs.is_file(src_entry.path, follow_symlinks=False) == src_entry.is_file(follow_symlinks=False)
    assert vfs.is_file(src_entry.path, follow_symlinks=True) == src_entry.is_file(follow_symlinks=True)
    assert vfs.is_file(src_entry.path, follow_symlinks=True) == dst_entry.is_file(follow_symlinks=False)
    assert vfs.is_file(src_entry.path, follow_symlinks=True) == dst_entry.is_file(follow_symlinks=True)


@pytest.fixture
def virt_dir() -> VirtualDirectory:
    return VirtualDirectory(Mock(), "")


@pytest.fixture
def top_virt_dir() -> VirtualDirectory:
    return VirtualDirectory(Mock(), "")


def test_virutal_directory_stat(virt_dir: VirtualDirectory, top_virt_dir: VirtualDirectory) -> None:
    assert virt_dir.stat(follow_symlinks=False) == virt_dir._stat()
    assert virt_dir.stat(follow_symlinks=True) == virt_dir._stat()

    virt_dir.top = top_virt_dir
    assert virt_dir.stat(follow_symlinks=False) == top_virt_dir.stat(follow_symlinks=False)
    assert virt_dir.stat(follow_symlinks=True) == top_virt_dir.stat(follow_symlinks=True)


def test_virutal_directory_lstat(virt_dir: VirtualDirectory, top_virt_dir: VirtualDirectory) -> None:
    assert virt_dir.lstat() == virt_dir._stat()
    assert virt_dir.lstat() == virt_dir.stat(follow_symlinks=False)
    assert virt_dir.lstat().st_mode == stat.S_IFDIR

    virt_dir.top = top_virt_dir
    assert virt_dir.lstat() == top_virt_dir.lstat()


def test_virutal_directory_is_dir(virt_dir: VirtualDirectory) -> None:
    assert virt_dir.is_dir(follow_symlinks=True)
    assert virt_dir.is_dir(follow_symlinks=False)


def test_virutal_directory_is_file(virt_dir: VirtualDirectory):
    assert not virt_dir.is_file(follow_symlinks=True)
    assert not virt_dir.is_file(follow_symlinks=False)


@pytest.fixture
def virt_file() -> VirtualFile:
    return VirtualFile(Mock(), "", Mock())


def test_virutal_file_stat(virt_file: VirtualFile) -> None:
    assert virt_file.stat(follow_symlinks=False) == virt_file.lstat()
    assert virt_file.stat(follow_symlinks=True) == virt_file.lstat()


def test_virutal_file_lstat(virt_file: VirtualFile) -> None:
    assert virt_file.lstat().st_mode == stat.S_IFREG


def test_virutal_file_is_dir(virt_file: VirtualFile) -> None:
    assert not virt_file.is_dir(follow_symlinks=True)
    assert not virt_file.is_dir(follow_symlinks=False)


def test_virutal_file_is_file(virt_file: VirtualFile) -> None:
    assert virt_file.is_file(follow_symlinks=True)
    assert virt_file.is_file(follow_symlinks=False)


def test_virtual_symlink_stat(filelink_entry: VirtualSymlink, file_entry: Union[VirtualFile, VirtualDirectory]) -> None:
    assert filelink_entry.stat(follow_symlinks=False) == filelink_entry.lstat()
    assert filelink_entry.stat(follow_symlinks=True) == file_entry.stat()


def test_virtual_symlink_lstat(filelink_entry: VirtualSymlink) -> None:
    assert filelink_entry.lstat().st_mode == stat.S_IFLNK


@pytest.mark.parametrize(
    "virt_link, is_dir",
    (
        ("dirlink_entry", True),
        ("filelink_entry", False),
    ),
)
def test_virtual_symlink_is_dir(virt_link: str, is_dir: bool, request: FixtureRequest) -> None:
    virt_link = request.getfixturevalue(virt_link)

    assert virt_link.is_dir(follow_symlinks=False) is False
    assert virt_link.is_dir(follow_symlinks=True) == is_dir


@pytest.mark.parametrize(
    "virt_link, is_file",
    (
        ("dirlink_entry", False),
        ("filelink_entry", True),
    ),
)
def test_virtual_symlink_is_file(virt_link: str, is_file: bool, request: FixtureRequest) -> None:
    virt_link = request.getfixturevalue(virt_link)

    assert virt_link.is_file(follow_symlinks=False) is False
    assert virt_link.is_file(follow_symlinks=True) == is_file


@pytest.fixture
def vfs1() -> VirtualFilesystem:
    return VirtualFilesystem()


@pytest.fixture
def vfs2() -> VirtualFilesystem:
    return VirtualFilesystem()


@pytest.fixture
def vfs1_entry(vfs1: VirtualFilesystem) -> VirtualFile:
    return VirtualFile(vfs1, "vfs1_entry", Mock())


@pytest.fixture
def vfs2_entry(vfs2: VirtualFilesystem) -> VirtualFile:
    return VirtualFile(vfs2, "vfs2_entry", Mock())


@pytest.fixture
def rootfs(
    vfs1: VirtualFilesystem,
    vfs2: VirtualFilesystem,
    vfs1_entry: VirtualFile,
    vfs2_entry: VirtualFile,
) -> RootFilesystem:
    vfs1.map_file_entry("/vfs1_entry", vfs1_entry)
    vfs1.symlink("/vfs1/vfs2/", "/link_to_vfs2")

    vfs2.map_file_entry("/vfs2_entry", vfs2_entry)
    vfs2_shared_entry = VirtualFile(vfs2, "shared_entry", Mock())
    vfs2.map_file_entry("/shared_entry", vfs2_shared_entry)

    vfs1.map_file_entry("/path/to/some/file", VirtualFile(vfs1, "path/to/some/file", Mock()))
    vfs1.symlink("/path/to/some/", "dirlink")
    vfs1.symlink("/path/to/some/file", "filelink")

    target = Mock()
    rootfs = RootFilesystem(target)
    rootfs.mount("/vfs1", vfs1)
    rootfs.mount("/vfs1/vfs2", vfs2)
    return rootfs


def test_root_filesystem_get(
    rootfs: RootFilesystem,
    vfs1: VirtualFilesystem,
    vfs1_entry: VirtualFile,
    vfs2_entry: VirtualFile,
):
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
    vfs1_link = vfs1.get("/link_to_vfs2")
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


@pytest.fixture
def root_dir_entry(rootfs: RootFilesystem) -> VirtualDirectory:
    return rootfs.get("/vfs1/path/to/some")


@pytest.fixture
def root_dirlink_entry(rootfs: RootFilesystem) -> VirtualSymlink:
    return rootfs.get("/vfs1/dirlink")


@pytest.fixture
def root_file_entry(rootfs: RootFilesystem) -> VirtualFile:
    return rootfs.get("/vfs1/path/to/some/file")


@pytest.fixture
def root_filelink_entry(rootfs: RootFilesystem) -> VirtualSymlink:
    return rootfs.get("/vfs1/filelink")


@pytest.mark.parametrize(
    "src_entry, dst_entry",
    [
        ("root_dir_entry", "root_dir_entry"),
        ("root_dirlink_entry", "root_dir_entry"),
        ("root_file_entry", "root_file_entry"),
        ("root_filelink_entry", "root_file_entry"),
    ],
)
def test_root_filesystem_entry_stat(src_entry: str, dst_entry: str, request: FixtureRequest) -> None:
    src_entry = request.getfixturevalue(src_entry)
    dst_entry = request.getfixturevalue(dst_entry)

    assert src_entry.stat(follow_symlinks=False) == src_entry.lstat()
    assert src_entry.stat(follow_symlinks=True) == dst_entry.stat()


@pytest.mark.parametrize(
    "entry, st_mode",
    [
        ("root_dir_entry", stat.S_IFDIR),
        ("root_dirlink_entry", stat.S_IFLNK),
        ("root_file_entry", stat.S_IFREG),
    ],
)
def test_root_filesystem_entry_lstat(entry: str, st_mode: int, request: FixtureRequest) -> None:
    entry = request.getfixturevalue(entry)

    assert entry.lstat().st_mode == st_mode


@pytest.mark.parametrize(
    "entry, src_is_dir, dst_is_dir",
    [
        ("root_dir_entry", True, True),
        ("root_dirlink_entry", False, True),
        ("root_file_entry", False, False),
        ("root_filelink_entry", False, False),
    ],
)
def test_root_filesystem_entry_is_dir(entry: str, src_is_dir: bool, dst_is_dir: bool, request: FixtureRequest) -> None:
    entry = request.getfixturevalue(entry)

    assert entry.is_dir(follow_symlinks=False) == src_is_dir
    assert entry.is_dir(follow_symlinks=True) == dst_is_dir


@pytest.mark.parametrize(
    "entry, src_is_file, dst_is_file",
    [
        ("root_dir_entry", False, False),
        ("root_dirlink_entry", False, False),
        ("root_file_entry", True, True),
        ("root_filelink_entry", False, True),
    ],
)
def test_root_filesystem_entry_is_file(
    entry: str,
    src_is_file: bool,
    dst_is_file: bool,
    request: FixtureRequest,
) -> None:
    entry = request.getfixturevalue(entry)

    assert entry.is_file(follow_symlinks=False) == src_is_file
    assert entry.is_file(follow_symlinks=True) == dst_is_file


@pytest.fixture
def mapped_file() -> MappedFile:
    return MappedFile(Mock(), "/some/path", Mock())


def test_mapped_file_stat(mapped_file: MappedFile) -> None:
    mock_stat = Mock()

    with patch("dissect.target.helpers.fsutil.stat_result.copy", autospec=True) as stat_copy:
        with patch("os.stat", autospec=True, return_value=mock_stat) as os_stat:
            with patch("os.lstat", autospec=True, return_value=mock_stat) as os_lstat:
                mapped_file.stat(follow_symlinks=False)
                os_lstat.assert_called_with(mapped_file.entry)
                stat_copy.assert_called_with(mock_stat)

                mapped_file.stat(follow_symlinks=True)
                os_stat.assert_called_with(mapped_file.entry)
                stat_copy.assert_called_with(mock_stat)


def test_mapped_file_lstat(mapped_file: MappedFile) -> None:
    mock_stat = Mock()

    with patch("dissect.target.helpers.fsutil.stat_result.copy", autospec=True) as stat_copy:
        with patch("os.lstat", autospec=True, return_value=mock_stat) as os_lstat:
            mapped_file.lstat()
            os_lstat.assert_called_with(mapped_file.entry)
            stat_copy.assert_called_with(mock_stat)


def test_mapped_file_attr(mapped_file: MappedFile) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        mapped_file.attr()
        fs_attrs.assert_called_with(mapped_file.entry, follow_symlinks=True)


def test_mapped_file_lattr(mapped_file: MappedFile) -> None:
    with patch("dissect.target.helpers.fsutil.fs_attrs", autospec=True) as fs_attrs:
        mapped_file.lattr()
        fs_attrs.assert_called_with(mapped_file.entry, follow_symlinks=False)


def test_reset_file_position() -> None:
    fh = BytesIO(b"\x00" * 8192)
    fh.seek(512)

    class MockFilesystem(filesystem.Filesystem):
        def __init__(self, fh):
            assert fh.tell() == 0
            fh.seek(1024)
            self.success = True

        @staticmethod
        def _detect(fh):
            assert fh.tell() == 0
            fh.seek(256)
            return True

    mock_fs = Mock()
    mock_fs.MockFilesystem = MockFilesystem

    with patch.object(filesystem, "FILESYSTEMS", [mock_fs.MockFilesystem]):
        opened_fs = filesystem.open(fh)
        assert isinstance(opened_fs, mock_fs.MockFilesystem)
        assert opened_fs.success
        assert fh.tell() == 512
