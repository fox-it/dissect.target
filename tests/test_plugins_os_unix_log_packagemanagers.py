from dissect.target.plugins.os.unix.log.packagemanagers.apt import AptPlugin
from dissect.target.plugins.os.unix.log.packagemanagers.model import (
    PackageManagerLogRecord,
)
from dissect.target.plugins.os.unix.log.packagemanagers.yum import YumPlugin
from dissect.target.plugins.os.unix.log.packagemanagers.zypper import ZypperPlugin

from ._utils import absolute_path

empty_record = PackageManagerLogRecord()


def test_plugins_os_unix_log_packagemanagers_apt_txt(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log")
    fs_unix.map_file("/var/log/apt/history.log", data_file)
    target_unix.add_plugin(AptPlugin)

    results = list(target_unix.apt())
    assert len(results) == 18

    for record in results:
        assert record.package_manager == "apt"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_apt_gz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log.gz")
    fs_unix.map_file("/var/log/apt/history.log.1.gz", data_file)
    target_unix.add_plugin(AptPlugin)

    results = list(target_unix.apt())
    assert len(results) == 18

    for record in results:
        assert record.package_manager == "apt"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_apt_bz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log.bz2")
    fs_unix.map_file("/var/log/apt/history.log.1.bz2", data_file)
    target_unix.add_plugin(AptPlugin)

    results = list(target_unix.apt())
    assert len(results) == 18

    for record in results:
        assert record.package_manager == "apt"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_yum_txt(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log")
    fs_unix.map_file("/var/log/yum.log", data_file)
    target_unix.add_plugin(YumPlugin)

    results = list(target_unix.yum())
    assert len(results) == 5

    for record in results:
        assert record.package_manager == "yum"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_yum_gz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log.gz")
    fs_unix.map_file("/var/log/yum.log.1.gz", data_file)
    target_unix.add_plugin(YumPlugin)

    results = list(target_unix.yum())
    assert len(results) == 5

    for record in results:
        assert record.package_manager == "yum"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_yum_bz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log.bz2")
    fs_unix.map_file("/var/log/yum.log.1.bz2", data_file)
    target_unix.add_plugin(YumPlugin)

    results = list(target_unix.yum())
    assert len(results) == 5

    for record in results:
        assert record.package_manager == "yum"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_zypper_txt(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history")
    fs_unix.map_file("/var/log/zypp/history", data_file)
    target_unix.add_plugin(ZypperPlugin)

    results = list(target_unix.zypper())
    assert len(results) == 61

    for record in results:
        assert record.package_manager == "zypper"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_zypper_gz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history.gz")
    fs_unix.map_file("/var/log/zypp/history.1.gz", data_file)
    target_unix.add_plugin(ZypperPlugin)

    results = list(target_unix.zypper())
    assert len(results) == 61

    for record in results:
        assert record.package_manager == "zypper"
        assert isinstance(record, type(empty_record))


def test_plugins_os_unix_log_packagemanagers_zypper_bz(target_unix, fs_unix):
    data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history.bz2")
    fs_unix.map_file("/var/log/zypp/history.1.bz2", data_file)
    target_unix.add_plugin(ZypperPlugin)

    results = list(target_unix.zypper())
    assert len(results) == 61

    for record in results:
        assert record.package_manager == "zypper"
        assert isinstance(record, type(empty_record))
