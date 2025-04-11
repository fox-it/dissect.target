from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.trash import GnomeTrashPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_gnome_trash(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if GNOME Trash plugin finds all deleted files including recursively deleted folders and expunged items."""

    fs_unix.map_file_fh("etc/hostname", BytesIO(b"hostname"))
    fs_unix.map_dir("home/user/.local/share/Trash", absolute_path("_data/plugins/os/unix/trash"))
    target_unix_users.add_plugin(UnixPlugin)
    target_unix_users.add_plugin(GnomeTrashPlugin)

    # test if the plugin and its alias were registered
    assert target_unix_users.has_function("trash")
    assert target_unix_users.has_function("recyclebin")

    results = sorted(target_unix_users.trash(), key=lambda r: r.source)
    assert len(results) == 11

    # test if we find a deleted file
    assert results[2].ts == datetime(2024, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert results[2].path == "/home/user/Documents/some-location/another-file.bin"
    assert results[2].filesize == 369
    assert results[2].deleted_path == "/home/user/.local/share/Trash/files/another-file.bin"
    assert results[2].source == "/home/user/.local/share/Trash/info/another-file.bin.trashinfo"
    assert results[2].username == "user"
    assert results[2].hostname == "hostname"

    # test if we still find a file by just the .trashinfo file and no entry in the $Trash/files folder
    assert results[6].path == "/home/user/Downloads/missing-file.txt"
    assert results[6].filesize == 0
    assert results[6].source == "/home/user/.local/share/Trash/info/missing-file.txt.trashinfo"

    # test if we find a deleted directory
    assert results[7].ts == datetime(2024, 12, 31, 1, 2, 3, tzinfo=timezone.utc)
    assert results[7].path == "/home/user/Downloads/some-dir"
    assert results[7].filesize is None
    assert results[7].deleted_path == "/home/user/.local/share/Trash/files/some-dir"
    assert results[7].source == "/home/user/.local/share/Trash/info/some-dir.trashinfo"
    assert results[7].username == "user"
    assert results[7].hostname == "hostname"

    # test if we find files nested inside a deleted directory
    deleted_paths = [r.deleted_path for r in results]
    assert deleted_paths == [
        "/home/user/.local/share/Trash/expunged/123456789/some-dir",
        "/home/user/.local/share/Trash/expunged/123456789/some-dir/some-file.txt",
        "/home/user/.local/share/Trash/files/another-file.bin",
        "/home/user/.local/share/Trash/files/example.jpg",
        "/home/user/.local/share/Trash/files/file.txt.2",
        "/home/user/.local/share/Trash/files/file.txt",
        "/home/user/.local/share/Trash/files/missing-file.txt",
        "/home/user/.local/share/Trash/files/some-dir",
        "/home/user/.local/share/Trash/files/some-dir/another-dir",
        "/home/user/.local/share/Trash/files/some-dir/some-file.txt",
        "/home/user/.local/share/Trash/files/some-dir/another-dir/another-file.txt",
    ]

    # test if we find two deleted files that had the same basename
    assert results[4].path == "/home/user/Desktop/file.txt"
    assert results[4].deleted_path == "/home/user/.local/share/Trash/files/file.txt.2"
    assert results[4].filesize == 10
    assert results[5].path == "/home/user/Documents/file.txt"
    assert results[5].deleted_path == "/home/user/.local/share/Trash/files/file.txt"
    assert results[5].filesize == 20

    # test if we find expunged files
    assert results[0].path is None
    assert results[0].deleted_path == "/home/user/.local/share/Trash/expunged/123456789/some-dir"
    assert results[1].path is None
    assert results[1].deleted_path == "/home/user/.local/share/Trash/expunged/123456789/some-dir/some-file.txt"
    assert results[1].filesize == 79


def test_gnome_trash_mounts(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if GNOME Trash plugin finds Trash files in mounted devices from ``/etc/fstab``, ``/mnt`` and ``/media``."""

    fs_unix.map_file_fh("etc/hostname", BytesIO(b"hostname"))
    fs_unix.map_dir("home/user/.local/share/Trash", absolute_path("_data/plugins/os/unix/trash"))
    fs_unix.map_dir("mnt/example/.Trash-1234", absolute_path("_data/plugins/os/unix/trash"))
    fs_unix.map_dir("tmp/example/.Trash-5678", absolute_path("_data/plugins/os/unix/trash"))
    fs_unix.map_dir("media/user/example/.Trash-1000", absolute_path("_data/plugins/os/unix/trash"))

    with patch.object(target_unix_users.fs, "mounts", {"/tmp/example": None, "/mnt/example": None}):
        target_unix_users.add_plugin(UnixPlugin)
        plugin = GnomeTrashPlugin(target_unix_users)

        assert sorted([str(t) for _, t in plugin.trashes]) == [
            "/home/user/.local/share/Trash",
            "/media/user/example/.Trash-1000",
            "/mnt/example/.Trash-1234",
            "/tmp/example/.Trash-5678",
        ]

        assert len(list(plugin.trash())) == 11 * len(plugin.trashes)
