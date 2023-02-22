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
def test_zypper_logs(test_file, target_unix, fs_unix):
    data_file = absolute_path(f"data/plugins/os/unix/linux/suse/zypp/{test_file}")
    fs_unix.map_file(f"/var/log/zypp/{test_file}", data_file)
    target_unix.add_plugin(ZypperPlugin)

    results = list(target_unix.zypper.logs())
    assert len(results) == 61

    for record in results:
        assert record.package_manager == "zypper"
