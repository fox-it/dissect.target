from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.target.plugins.os.unix.generic import GenericPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

# The mtime of the file in the checkout, converted like the plugin does. datetime.fromtimestamp() rounds to the
# nearest microsecond instead of down, so it can differ by a microsecond depending on when the file was checked out
log_mtime = absolute_path("_data/plugins/os/unix/log/empty.log").stat().st_mtime


def test_unix_generic_activity(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/log/some.log", absolute_path("_data/plugins/os/unix/log/empty.log"))
    target_unix.add_plugin(GenericPlugin)
    assert target_unix.activity == from_unix(log_mtime)


def test_unix_generic_install_date(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file("/var/log/installer/syslog", absolute_path("_data/plugins/os/unix/log/empty.log"))
    target_unix.add_plugin(GenericPlugin)
    assert target_unix.install_date == from_unix(log_mtime)
