from dissect.target.plugins.os.unix.log.packagemanagers.apt import AptPlugin
from dissect.target.plugins.os.unix.log.packagemanagers.model import PackageManagerLogRecord
from dissect.target.plugins.os.unix.log.packagemanagers.yum import YumPlugin
from dissect.target.plugins.os.unix.log.packagemanagers.zypper import ZypperPlugin

from ._utils import absolute_path

empty_record = PackageManagerLogRecord()


def assert_correct_type(record):
    assert type(record) == type(empty_record)


class TestApt:
    def test_txt(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log")
        fs_unix.map_file("/var/log/apt/history.log", data_file)
        target_unix.add_plugin(AptPlugin)

        results = list(target_unix.apt())
        assert len(results) == 18

        for record in results:
            assert record.package_manager == "apt"
            assert_correct_type(record)

    def test_gzipped(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log.gz")
        fs_unix.map_file("/var/log/apt/history.log.1.gz", data_file)
        target_unix.add_plugin(AptPlugin)

        results = list(target_unix.apt())
        assert len(results) == 18

        for record in results:
            assert record.package_manager == "apt"
            assert_correct_type(record)

    def test_bzip2(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/apt/history.log.bz2")
        fs_unix.map_file("/var/log/apt/history.log.1.bz2", data_file)
        target_unix.add_plugin(AptPlugin)

        results = list(target_unix.apt())
        assert len(results) == 18

        for record in results:
            assert record.package_manager == "apt"
            assert_correct_type(record)


class TestYum:
    def test_txt(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log")
        fs_unix.map_file("/var/log/yum.log", data_file)
        target_unix.add_plugin(YumPlugin)

        results = list(target_unix.yum())
        assert len(results) == 5

        for record in results:
            assert record.package_manager == "yum"
            assert_correct_type(record)

    def test_gzipped(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log.gz")
        fs_unix.map_file("/var/log/yum.log.1.gz", data_file)
        target_unix.add_plugin(YumPlugin)

        results = list(target_unix.yum())
        assert len(results) == 5

        for record in results:
            assert record.package_manager == "yum"
            assert_correct_type(record)

    def test_bzip2(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/yum/yum.log.bz2")
        fs_unix.map_file("/var/log/yum.log.1.bz2", data_file)
        target_unix.add_plugin(YumPlugin)

        results = list(target_unix.yum())
        assert len(results) == 5

        for record in results:
            assert record.package_manager == "yum"
            assert_correct_type(record)


class TestZypper:
    data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history")

    def test_txt(self, target_unix, fs_unix):
        fs_unix.map_file("/var/log/zypp/history", self.data_file)
        target_unix.add_plugin(ZypperPlugin)

        results = list(target_unix.zypper())
        assert len(results) == 61

        for record in results:
            assert record.package_manager == "zypper"
            assert_correct_type(record)

    def test_gzipped(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history.gz")
        fs_unix.map_file("/var/log/zypp/history.1.gz", data_file)
        target_unix.add_plugin(ZypperPlugin)

        results = list(target_unix.zypper())
        assert len(results) == 61

        for record in results:
            assert record.package_manager == "zypper"
            assert_correct_type(record)

    def test_bzip2(self, target_unix, fs_unix):
        data_file = absolute_path("data/unix-logs/packagemanagers/zypp/history.bz2")
        fs_unix.map_file("/var/log/zypp/history.1.bz2", data_file)
        target_unix.add_plugin(ZypperPlugin)

        results = list(target_unix.zypper())
        assert len(results) == 61

        for record in results:
            assert record.package_manager == "zypper"
            assert_correct_type(record)
