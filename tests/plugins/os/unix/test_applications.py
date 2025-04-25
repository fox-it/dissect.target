from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.applications import UnixApplicationsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_unix_applications_desktop_files(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if .desktop files registering installed applications are detected correctly."""

    fs_unix.map_file_fh("/etc/hostname", BytesIO(b"hostname"))

    # system paths
    fs_unix.map_file(
        "/var/lib/snapd/desktop/applications/firefox_firefox.desktop",
        absolute_path("_data/plugins/os/unix/applications/firefox_firefox.desktop"),
    )
    fs_unix.map_file(
        "/var/lib/snapd/desktop/applications/code_code.desktop",
        absolute_path("_data/plugins/os/unix/applications/code_code.desktop"),
    )
    fs_unix.map_file(
        "/usr/share/applications/gimp.desktop",
        absolute_path("_data/plugins/os/unix/applications/gimp.desktop"),
    )
    fs_unix.map_file(
        "/usr/local/share/applications/vmware-workstation.desktop",
        absolute_path("_data/plugins/os/unix/applications/vmware-workstation.desktop"),
    )
    fs_unix.map_file(
        "/var/lib/flatpak/exports/share/applications/python.desktop",
        absolute_path("_data/plugins/os/unix/applications/python.desktop"),
    )

    # user paths
    fs_unix.map_file(
        "/home/user/.local/share/applications/vlc.desktop",
        absolute_path("_data/plugins/os/unix/applications/vlc.desktop"),
    )
    fs_unix.map_file(
        "/root/.local/share/applications/terminal.desktop",
        absolute_path("_data/plugins/os/unix/applications/terminal.desktop"),
    )

    target_unix_users.add_plugin(UnixPlugin)
    target_unix_users.add_plugin(UnixApplicationsPlugin)
    results = sorted(target_unix_users.applications(), key=lambda r: r.name)

    assert len(results) == 7

    assert results[0].ts_installed is None
    assert results[0].name == "Firefox Web Browser"
    assert results[0].version == "1.0"
    assert results[0].author is None
    assert results[0].type == "user"
    assert (
        results[0].path
        == "env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/firefox_firefox.desktop /snap/bin/firefox %u"
    )
    assert results[0].hostname == "hostname"

    assert [r.name for r in results] == [
        "Firefox Web Browser",
        "GNU Image Manipulation Program",
        "Python (v3.12)",
        "Terminal",
        "VLC media player",
        "VMware Workstation",
        "Visual Studio Code",
    ]

    assert [r.path for r in results] == [
        "env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/firefox_firefox.desktop /snap/bin/firefox %u",
        "gimp-2.10 %U",
        "/usr/bin/python3.12",
        "gnome-terminal",
        "/usr/bin/vlc --started-from-file %U",
        "/usr/bin/vmware %U",
        "env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/code_code.desktop /snap/bin/code --force-user-env %F",  # noqa: E501
    ]

    assert [r.type for r in results] == [
        "user",
        "user",
        "user",
        "system",
        "user",
        "user",
        "user",
    ]
