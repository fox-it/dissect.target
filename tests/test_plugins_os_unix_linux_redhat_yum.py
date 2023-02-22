import pytest

from dissect.target.plugins.os.unix.linux.redhat.yum import YumPlugin

from ._utils import absolute_path


@pytest.mark.parametrize(
    "test_file",
    [
        "yum.log",
        "yum.log.1.gz",
        "yum.log.1.bz2",
    ],
)
def test_yum_logs(test_file, target_unix, fs_unix):
    data_file = absolute_path(f"data/plugins/os/unix/linux/redhat/yum/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)
    target_unix.add_plugin(YumPlugin)

    results = list(target_unix.yum.logs())
    assert len(results) == 5

    for record in results:
        assert record.package_manager == "yum"
