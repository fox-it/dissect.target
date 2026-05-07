from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

PeriodicScriptsRecord = TargetRecordDescriptor(
    "macos/periodic_scripts",
    [
        ("path", "source"),
    ],
)

PeriodicConfRecord = TargetRecordDescriptor(
    "macos/periodic_conf",
    [
        ("string", "local_periodic"),
        ("string", "dir_output"),
        ("boolean", "dir_show_success"),
        ("boolean", "dir_show_info"),
        ("boolean", "dir_show_badconfig"),
        ("varint", "anticongestion_sleeptime"),
        ("path", "source"),
    ],
)

PeriodicConfDailyRecord = TargetRecordDescriptor(
    "macos/periodic_conf/daily",
    [
        ("boolean", "daily_clean_disks_enable"),
        ("string", "daily_clean_disks_files"),
        ("varint", "daily_clean_disks_days"),
        ("boolean", "daily_clean_disks_verbose"),
        ("boolean", "daily_clean_tmps_enable"),
        ("string", "daily_clean_tmps_dirs"),
        ("varint", "daily_clean_tmps_days"),
        ("string", "daily_clean_tmps_ignore"),
        ("boolean", "daily_clean_tmps_verbose"),
        ("boolean", "daily_clean_preserve_enable"),
        ("varint", "daily_clean_preserve_days"),
        ("boolean", "daily_clean_preserve_verbose"),
        ("boolean", "daily_clean_msgs_enable"),
        ("varint", "daily_clean_msgs_days"),
        ("boolean", "daily_clean_rwho_enable"),
        ("varint", "daily_clean_rwho_days"),
        ("boolean", "daily_clean_rwho_verbose"),
        ("boolean", "daily_clean_hoststat_enable"),
        ("boolean", "daily_backup_efi_enable"),
        ("boolean", "daily_backup_gmirror_enable"),
        ("boolean", "daily_backup_gmirror_verbose"),
        ("boolean", "daily_backup_gpart_enable"),
        ("boolean", "daily_backup_gpart_verbose"),
        ("boolean", "daily_backup_passwd_enable"),
        ("boolean", "daily_backup_aliases_enable"),
        ("boolean", "daily_backup_zfs_enable"),
        ("string", "daily_backup_zfs_list_flags"),
        ("string", "daily_backup_zpool_list_flags"),
        ("boolean", "daily_backup_zfs_props_enable"),
        ("string", "daily_backup_zfs_get_flags"),
        ("string", "daily_backup_zpool_get_flags"),
        ("boolean", "daily_backup_zfs_verbose"),
        ("boolean", "daily_calendar_enable"),
        ("boolean", "daily_accounting_enable"),
        ("boolean", "daily_accounting_compress"),
        ("varint", "daily_accounting_save"),
        ("string", "daily_accounting_flags"),
        ("boolean", "daily_status_disks_enable"),
        ("string", "daily_status_disks_df_flags"),
        ("boolean", "daily_status_zfs_enable"),
        ("boolean", "daily_status_zfs_zpool_list_enable"),
        ("boolean", "daily_status_gmirror_enable"),
        ("boolean", "daily_status_graid3_enable"),
        ("boolean", "daily_status_gstripe_enable"),
        ("boolean", "daily_status_gconcat_enable"),
        ("boolean", "daily_status_mfi_enable"),
        ("boolean", "daily_status_network_enable"),
        ("string", "daily_status_network_netstat_flags"),
        ("boolean", "daily_status_network_usedns"),
        ("boolean", "daily_status_uptime_enable"),
        ("boolean", "daily_status_mailq_enable"),
        ("boolean", "daily_status_mailq_shorten"),
        ("boolean", "daily_status_include_submit_mailq"),
        ("boolean", "daily_status_security_enable"),
        ("boolean", "daily_status_security_inline"),
        ("string", "daily_status_security_output"),
        ("boolean", "daily_status_mail_rejects_enable"),
        ("varint", "daily_status_mail_rejects_logs"),
        ("boolean", "daily_status_ntpd_enable"),
        ("boolean", "daily_status_world_kernel"),
        ("boolean", "daily_queuerun_enable"),
        ("boolean", "daily_submit_queuerun"),
        ("boolean", "daily_scrub_zfs_enable"),
        ("string", "daily_scrub_zfs_pools"),
        ("varint", "daily_scrub_zfs_default_threshold"),
        ("boolean", "daily_trim_zfs_enable"),
        ("string", "daily_trim_zfs_pools"),
        ("string", "daily_local"),
        ("string", "daily_diff_flags"),
        ("path", "source"),
    ],
)

PeriodicConfWeeklyRecord = TargetRecordDescriptor(
    "macos/periodic_conf/weekly",
    [
        ("boolean", "weekly_locate_enable"),
        ("boolean", "weekly_whatis_enable"),
        ("boolean", "weekly_noid_enable"),
        ("string", "weekly_noid_dirs"),
        ("boolean", "weekly_status_security_enable"),
        ("boolean", "weekly_status_security_inline"),
        ("string", "weekly_status_security_output"),
        ("boolean", "weekly_status_pkg_enable"),
        ("string", "pkg_version"),
        ("string", "pkg_version_index"),
        ("string", "weekly_local"),
        ("path", "source"),
    ],
)

PeriodicConfMonthlyRecord = TargetRecordDescriptor(
    "macos/periodic_conf/monthly",
    [
        ("boolean", "monthly_accounting_enable"),
        ("boolean", "monthly_status_security_enable"),
        ("boolean", "monthly_status_security_inline"),
        ("string", "monthly_status_security_output"),
        ("string", "monthly_local"),
        ("path", "source"),
    ],
)

PeriodicConfSecurityRecord = TargetRecordDescriptor(
    "macos/periodic_conf/security",
    [
        ("string", "security_status_diff_flags"),
        ("boolean", "security_status_chksetuid_enable"),
        ("string", "security_status_chksetuid_period"),
        ("boolean", "security_status_chkportsum_enable"),
        ("string", "security_status_chkportsum_period"),
        ("boolean", "security_status_neggrpperm_enable"),
        ("string", "security_status_neggrpperm_period"),
        ("boolean", "security_status_chkmounts_enable"),
        ("string", "security_status_chkmounts_period"),
        ("boolean", "security_status_noamd"),
        ("boolean", "security_status_chkuid0_enable"),
        ("string", "security_status_chkuid0_period"),
        ("boolean", "security_status_passwdless_enable"),
        ("string", "security_status_passwdless_period"),
        ("boolean", "security_status_logincheck_enable"),
        ("string", "security_status_logincheck_period"),
        ("boolean", "security_status_ipfwdenied_enable"),
        ("string", "security_status_ipfwdenied_period"),
        ("boolean", "security_status_ipfdenied_enable"),
        ("string", "security_status_ipfdenied_period"),
        ("boolean", "security_status_pfdenied_enable"),
        ("string", "security_status_pfdenied_additionalanchors"),
        ("string", "security_status_pfdenied_period"),
        ("boolean", "security_status_ipfwlimit_enable"),
        ("string", "security_status_ipfwlimit_period"),
        ("boolean", "security_status_kernelmsg_enable"),
        ("string", "security_status_kernelmsg_period"),
        ("boolean", "security_status_loginfail_enable"),
        ("string", "security_status_loginfail_period"),
        ("boolean", "security_status_tcpwrap_enable"),
        ("string", "security_status_tcpwrap_period"),
        ("path", "source"),
    ],
)

PeriodicConfRecords = (
    PeriodicConfRecord,
    PeriodicConfDailyRecord,
    PeriodicConfWeeklyRecord,
    PeriodicConfMonthlyRecord,
    PeriodicConfSecurityRecord,
)


class PeriodicPlugin(Plugin):
    """macOS periodic plugin."""

    PERIODIC_SCRIPTS_PATHS = (
        "/etc/daily.local/*",
        "/etc/monthly.local/*",
        "/etc/periodic/**2",
        "/etc/periodic/daily/*",
        "/etc/periodic/monthly/*",
        "/etc/periodic/weekly/*",
        "/etc/weekly.local/*",
        "/usr/local/etc/periodic/**2",
    )

    PERIODIC_CONF_PATHS = (
        "/etc/defaults/periodic.conf",
        "/etc/periodic.conf",
        "/etc/periodic.conf.local",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.periodic_scripts_files = set()
        self.periodic_conf_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.periodic_scripts_files or self.periodic_conf_files):
            raise UnsupportedPluginError("No periodic files found")

    def _find_files(self) -> None:
        for pattern in self.PERIODIC_SCRIPTS_PATHS:
            for path in self.target.fs.glob(pattern):
                self.periodic_scripts_files.add(path)

        for path in self.PERIODIC_CONF_PATHS:
            p = self.target.fs.path(path)
            if p.exists():
                self.periodic_conf_files.add(p)

    @export(record=PeriodicScriptsRecord)
    def periodic_scripts(self) -> Iterator[PeriodicScriptsRecord]:
        """Yield macOS periodic script paths."""
        for file in self.periodic_scripts_files:
            yield PeriodicScriptsRecord(
                source=file,
            )

    @export(record=PeriodicConfRecords)
    def periodic_conf(self) -> Iterator[PeriodicConfRecords]:
        """Yield macOS periodic configuration information."""
        for file in self.periodic_conf_files:
            for record in PeriodicConfRecords:
                record_keys = set(record.fields.keys())
                record_dict = {}

                with file.open("r") as f:
                    for line in f:
                        line = line.strip()

                        if not line or line.startswith("#"):
                            continue

                        line = line.split("#", 1)[0].strip()

                        if "=" in line:
                            key, value = line.split("=", 1)
                            key = key.strip()

                            if key in record_keys:
                                value = value.strip().strip('"')
                                if value == "":
                                    continue
                                elif value == "YES":
                                    value = True
                                elif value == "NO":
                                    value = False
                                record_dict[key] = value

                    if record_dict:
                        record_dict["source"] = file
                        yield record(
                            **record_dict,
                        )
