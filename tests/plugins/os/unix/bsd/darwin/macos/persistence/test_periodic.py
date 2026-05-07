from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.persistence.periodic import PeriodicPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "199.rotate-fax",
                "110.clean-tmps",
            ),
            (
                "/etc/periodic/monthly/199.rotate-fax",
                "/etc/periodic/daily/110.clean-tmps",
            ),
        ),
    ],
)
def test_periodic_scripts(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/periodic/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(PeriodicPlugin)

        results = list(target_unix.periodic_scripts())
        results.sort(key=lambda r: r.source)

        assert len(results) == 2

        assert results[0].source == "/etc/periodic/daily/110.clean-tmps"

        assert results[1].source == "/etc/periodic/monthly/199.rotate-fax"


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("periodic.conf",),
            ("/etc/defaults/periodic.conf",),
        ),
    ],
)
def test_periodic_conf(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/periodic/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(PeriodicPlugin)

        results = list(target_unix.periodic_conf())
        results.sort(key=lambda r: r.source)

        assert len(results) == 4

        assert results[0].local_periodic == "/usr/local/etc/periodic"
        assert results[0].dir_output is None
        assert results[0].dir_show_success is None
        assert results[0].dir_show_info is None
        assert results[0].dir_show_badconfig is None
        assert results[0].anticongestion_sleeptime is None
        assert results[0].source == "/etc/defaults/periodic.conf"

        assert results[1].daily_clean_disks_enable is None
        assert results[1].daily_clean_disks_files is None
        assert results[1].daily_clean_disks_days is None
        assert results[1].daily_clean_disks_verbose is None
        assert results[1].daily_clean_tmps_enable
        assert results[1].daily_clean_tmps_dirs == "/tmp"
        assert results[1].daily_clean_tmps_days == 3
        assert results[1].daily_clean_tmps_ignore == "$daily_clean_tmps_ignore quota.user quota.group"
        assert results[1].daily_clean_tmps_verbose
        assert results[1].daily_clean_preserve_enable is None
        assert results[1].daily_clean_preserve_days is None
        assert results[1].daily_clean_preserve_verbose is None
        assert results[1].daily_clean_msgs_enable
        assert results[1].daily_clean_msgs_days is None
        assert results[1].daily_clean_rwho_enable
        assert results[1].daily_clean_rwho_days == 7
        assert results[1].daily_clean_rwho_verbose
        assert results[1].daily_clean_hoststat_enable is None
        assert results[1].daily_accounting_enable
        assert not results[1].daily_accounting_compress
        assert results[1].daily_accounting_save == 3
        assert results[1].daily_accounting_flags == "-q"
        assert results[1].daily_status_disks_enable
        assert results[1].daily_status_disks_df_flags == "-l -h"
        assert results[1].daily_status_network_enable
        assert results[1].daily_status_network_usedns
        assert results[1].daily_status_mailq_enable
        assert not results[1].daily_status_mailq_shorten
        assert results[1].daily_status_include_submit_mailq
        assert results[1].daily_local == "/etc/daily.local"
        assert results[1].source == "/etc/defaults/periodic.conf"

        assert results[2].weekly_locate_enable is None
        assert results[2].weekly_whatis_enable is None
        assert results[2].weekly_noid_enable is None
        assert results[2].weekly_noid_dirs is None
        assert results[2].weekly_status_security_enable is None
        assert results[2].weekly_status_security_inline is None
        assert results[2].weekly_status_security_output is None
        assert results[2].weekly_status_pkg_enable is None
        assert results[2].pkg_version is None
        assert results[2].pkg_version_index is None
        assert results[2].weekly_local == "/etc/weekly.local"
        assert results[2].source == "/etc/defaults/periodic.conf"

        assert results[3].monthly_accounting_enable
        assert results[3].monthly_status_security_enable is None
        assert results[3].monthly_status_security_inline is None
        assert results[3].monthly_status_security_output is None
        assert results[3].monthly_local == "/etc/monthly.local"
        assert results[3].source == "/etc/defaults/periodic.conf"
