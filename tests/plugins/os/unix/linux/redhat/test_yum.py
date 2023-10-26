from datetime import datetime, timezone

import pytest

from dissect.target.plugins.os.unix.linux.redhat.yum import YumPlugin
from tests._utils import absolute_path


@pytest.mark.parametrize(
    "test_file",
    [
        "yum.log",
        "yum.log.1.gz",
        "yum.log.1.bz2",
    ],
)
def test_yum_logs(test_file, target_unix, fs_unix) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/linux/redhat/yum/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)
    target_unix.add_plugin(YumPlugin)

    results = list(target_unix.yum.logs())
    assert len(results) == 5

    for record in results:
        assert record.package_manager == "yum"

    assert results[0].ts == datetime(2023, 12, 16, 4, 41, 34, tzinfo=tz)
    assert results[0].operation == "install"
    assert results[0].package_name == "unzip-6.0-24.el7_9.x86_64"
    assert results[0].command is None
    assert results[0].requested_by_user is None

    assert results[-1].ts == datetime(2023, 12, 16, 4, 41, 22, tzinfo=tz)
    assert results[-1].operation == "install"
    assert results[-1].package_name == "unzip-6.0-24.el7_9.x86_64"
    assert results[-1].command is None
    assert results[-1].requested_by_user is None
