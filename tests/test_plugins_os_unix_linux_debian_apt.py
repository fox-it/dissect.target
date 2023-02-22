import pytest

from dissect.target.plugins.os.unix.linux.debian.apt import AptPlugin

from ._utils import absolute_path


@pytest.mark.parametrize(
    "test_file",
    [
        "history.log",
        "history.log.1.gz",
        "history.log.1.bz2",
    ],
)
def test_apt_logs(test_file, target_unix, fs_unix):
    data_file = absolute_path(f"data/plugins/os/unix/linux/debian/apt/{test_file}")
    fs_unix.map_file(f"/var/log/apt/{test_file}", data_file)
    target_unix.add_plugin(AptPlugin)

    results = list(target_unix.apt.logs())
    assert len(results) == 18

    for record in results:
        assert record.package_manager == "apt"
