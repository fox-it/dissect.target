from dissect.target.filesystem import VirtualFile
from dissect.target.plugins.filesystem.walkfs import WalkFSPlugin


def test_walkfs_plugin(target_unix, fs_unix):
    fs_unix.map_file_entry("/path/to/some/file", VirtualFile(fs_unix, "file", None))
    fs_unix.map_file_entry("/path/to/some/other/file.ext", VirtualFile(fs_unix, "file.ext", None))
    fs_unix.map_file_entry("/root_file", VirtualFile(fs_unix, "root_file", None))
    fs_unix.map_file_entry("/other_root_file.ext", VirtualFile(fs_unix, "other_root_file.ext", None))
    fs_unix.map_file_entry("/.test/test.txt", VirtualFile(fs_unix, "test.txt", None))
    fs_unix.map_file_entry("/.test/.more.test.txt", VirtualFile(fs_unix, ".more.test.txt", None))

    target_unix.add_plugin(WalkFSPlugin)

    results = list(target_unix.walkfs())
    assert len(results) == 14
    assert sorted([r.path for r in results]) == [
        "/",
        "/.test",
        "/.test/.more.test.txt",
        "/.test/test.txt",
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
