from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.recentlyused import RecentlyUsedPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_recently_used(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Verify parsing of valid recently-used.xbel file"""
    data_file = absolute_path("_data/plugins/os/unix/linux/recently-used.xbel")
    fs_unix.map_file("/home/user/.local/share/recently-used.xbel", data_file)
    target_unix_users.add_plugin(RecentlyUsedPlugin)

    # Check expected length
    results = list(target_unix_users.recently_used())
    assert len(results) == 15

    # Sanity checks on first parsed record
    assert results[0].user == "user"
    assert results[0].href == "file:///home/sjaak/.profile"
    assert results[0].ts == dt("2023-10-18 13:12:41.905277Z")
    assert results[0].added == dt("2023-10-18 13:12:41.905276Z")
    assert results[0].modified == dt("2023-10-18 13:14:09.483576Z")
    assert results[0].visited == dt("2023-10-18 13:12:41.905277Z")
    assert results[0].mimetype == "text/plain"


def test_recently_used_invalid_data(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Verify that the plugin doesn't error out on invalid data"""
    data_file = absolute_path("_data/plugins/os/unix/linux/recently-used-invalid-data.xbel")
    fs_unix.map_file("/home/user/.local/share/recently-used.xbel", data_file)
    target_unix_users.add_plugin(RecentlyUsedPlugin)

    results = list(target_unix_users.recently_used())
    assert len(results) == 15


def test_recently_used_broken_xml(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Verify that the plugin doesn't error out on broken XML structure"""
    data_file = absolute_path("_data/plugins/os/unix/linux/recently-used-broken-xml.xbel")
    fs_unix.map_file("/home/user/.local/share/recently-used.xbel", data_file)
    target_unix_users.add_plugin(RecentlyUsedPlugin)

    results = list(target_unix_users.recently_used())
    assert len(results) == 0
