from dissect.target.plugins.os.unix.packagemanager import PackageManagerPlugin

from ._utils import absolute_path


def test_packagemanager_logs(target_unix, fs_unix):
    data_file = absolute_path("data/plugins/os/unix/linux/debian/apt/history.log")
    fs_unix.map_file("/var/log/apt/history.log", data_file)
    data_file = absolute_path("data/plugins/os/unix/linux/redhat/yum/yum.log")
    fs_unix.map_file("/var/log/yum.log", data_file)
    data_file = absolute_path("data/plugins/os/unix/linux/suse/zypp/history")
    fs_unix.map_file("/var/log/zypp/history", data_file)
    target_unix.add_plugin(PackageManagerPlugin)

    results = list(target_unix.packagemanager.logs())
    assert len(results) == 84
