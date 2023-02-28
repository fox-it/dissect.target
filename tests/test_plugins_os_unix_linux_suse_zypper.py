from datetime import datetime, timezone

import pytest

from dissect.target.plugins.os.unix.linux.suse.zypper import ZypperPlugin

from ._utils import absolute_path


@pytest.mark.parametrize(
    "test_file",
    [
        "history",
        "history.1.gz",
        "history.1.bz2",
    ],
)
def test_zypper_logs(test_file, target_unix, fs_unix) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"data/plugins/os/unix/linux/suse/zypp/{test_file}")
    fs_unix.map_file(f"/var/log/zypp/{test_file}", data_file)
    target_unix.add_plugin(ZypperPlugin)

    results = list(target_unix.zypper.logs())
    assert len(results) == 61

    for record in results:
        assert record.package_manager == "zypper"

    assert results[0].ts == datetime(2022, 12, 16, 12, 56, 23, tzinfo=tz)
    assert results[0].operation == "other"
    assert results[0].package_name is None
    assert results[0].command == "zypper install unzip"
    assert results[0].requested_by_user == "root"

    assert results[-1].ts == datetime(2022, 12, 16, 13, 2, 44, tzinfo=tz)
    assert results[-1].operation == "install"
    assert results[-1].package_name == "yast2-4.5.20-1.1:x86_64"
    assert results[-1].command is None
    assert results[-1].requested_by_user is None
