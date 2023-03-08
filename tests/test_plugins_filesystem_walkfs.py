from dissect.target.filesystem import VirtualFile
from dissect.target.loaders.tar import TarLoader
from dissect.target.plugins.filesystem.walkfs import WalkFSPlugin

from ._utils import absolute_path


def test_walkfs_plugin(target_unix, fs_unix):
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))

    target_unix.add_plugin(WalkFSPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 10
    assert sorted([r.path for r in results]) == [
        "/etc",
        "/other_root_file.ext",
        "/path",
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
        "/root_file",
        "/var",
    ]


def test_walkfs_ext_internal(target_unix, fs_unix):
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))

    target_unix.add_plugin(WalkFSPlugin)

    results = list(target_unix.walkfs_ext())
    assert len(results) == 10
    assert sorted([r.path for _, r in results]) == [
        "/etc",
        "/other_root_file.ext",
        "/path",
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
        "/root_file",
        "/var",
    ]

    results = list(target_unix.walkfs_ext(root="/path"))
    assert len(results) == 5
    assert sorted([r.path for _, r in results]) == [
        "/path/to",
        "/path/to/some",
        "/path/to/some/file",
        "/path/to/some/other",
        "/path/to/some/other/file.ext",
    ]

    results = list(target_unix.walkfs_ext(pattern="*.ext"))
    assert len(results) == 2
    assert sorted([r.path for _, r in results]) == [
        "/other_root_file.ext",
        "/path/to/some/other/file.ext",
    ]

    results = list(target_unix.walkfs_ext(root="/path", pattern="*.ext"))
    assert len(results) == 1
    assert sorted([r.path for _, r in results]) == [
        "/path/to/some/other/file.ext",
    ]


def test_walkfs_dot_folder(target_unix):
    archive_path = absolute_path("data/loaders/tar/test-archive-dot-folder.tgz")
    loader = TarLoader(archive_path)
    loader.map(target_unix)
    target_unix.add_plugin(WalkFSPlugin)
    results = list(target_unix.walkfs())

    assert len(target_unix.filesystems) == 2
    assert len(results) == 3
    assert target_unix.fs.path("/test.txt").exists()
