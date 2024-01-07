from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.packagemanager import PackageManagerPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_packagemanager_logs_debian(target_debian: Target, fs_debian: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/linux/debian/apt/history.log")
    fs_debian.map_file("/var/log/apt/history.log", data_file)
    target_debian.add_plugin(PackageManagerPlugin)

    results = list(target_debian.packagemanager.logs())
    assert len(results) == 18


def test_packagemanager_logs_redhat(target_redhat: Target, fs_redhat: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/linux/redhat/yum/yum.log")
    fs_redhat.map_file("/var/log/yum.log", data_file)
    target_redhat.add_plugin(PackageManagerPlugin)

    results = list(target_redhat.packagemanager.logs())
    assert len(results) == 5


def test_packagemanager_logs_suse(target_suse: Target, fs_suse: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/linux/suse/zypp/history")
    fs_suse.map_file("/var/log/zypp/history", data_file)
    target_suse.add_plugin(PackageManagerPlugin)

    results = list(target_suse.packagemanager.logs())
    assert len(results) == 61
