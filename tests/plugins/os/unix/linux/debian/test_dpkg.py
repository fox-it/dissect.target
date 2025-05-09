from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.debian.dpkg import (
    STATUS_FILE_NAME,
    DpkgPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_dpkg_plugin_status(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    status_file = absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg-status")

    fs_unix.map_file(STATUS_FILE_NAME, status_file)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.status())

    assert len(results) == 9
    assert {r.section for r in results} == {"admin", "utils", "libs", "libdevel"}
    assert {r.arch for r in results} == {"amd64", "all"}


def test_dpkg_plugin_log_plain(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg.log")
    fs_unix.map_file("/var/log/dpkg.log", log_file)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.log())

    assert len(results) == 362
    assert all(r.name for r in results)
    # no remove operations in this test set
    assert all(r.version for r in results)
    assert {r.operation for r in results} == {"install", "upgrade", "status"}
    assert {r.arch for r in results} == {"amd64", "all"}


def test_dpkg_plugin_log_gz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    log_file_gz = absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg.log.2.gz")
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
