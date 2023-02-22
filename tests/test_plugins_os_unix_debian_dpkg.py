from dissect.target.plugins.os.unix.linux.debian.dpkg import (
    STATUS_FILE_NAME,
    DpkgPlugin,
)

from ._utils import absolute_path


def test_dpkg_plugin_status(target_unix, fs_unix):
    status_file = absolute_path("data/unix/logs/dpkg-status")

    fs_unix.map_file(STATUS_FILE_NAME, status_file)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.status())

    assert len(results) == 9
    assert {r.section for r in results} == {"admin", "utils", "libs", "libdevel"}
    assert {r.arch for r in results} == {"amd64", "all"}


def test_dpkg_plugin_log_plain(target_unix, fs_unix):
    log_file = absolute_path("data/unix/logs/dpkg.log")
    fs_unix.map_file("/var/log/dpkg.log", log_file)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.log())

    assert len(results) == 362
    assert all(r.name for r in results)
    # no remove operations in this test set
    assert all(r.version for r in results)
    assert {r.operation for r in results} == {"install", "upgrade", "status"}
    assert {r.arch for r in results} == {"amd64", "all"}


def test_dpkg_plugin_log_gz(target_unix, fs_unix):
    log_file_gz = absolute_path("data/unix/logs/dpkg.log.2.gz")
    fs_unix.map_file("/var/log/dpkg.log.2.gz", log_file_gz)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.log())

    assert len(results) == 97
    assert all(r.name for r in results)

    # remove operations are in the test set
    seen_versions = {r.version for r in results}
    assert None in seen_versions
    assert len(seen_versions) > 1

    assert {r.operation for r in results} == {"trigproc", "upgrade", "status", "remove"}
    assert {r.arch for r in results} == {"amd64", "all"}
