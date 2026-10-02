from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

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

# Part of the official FreeBSD periodic.conf documentation.
# Used by scripts in /etc/periodic/security.
# I was not able to find this folder nor these fields on a macOS Ventura system however.
# TODO: Look into this and remove this record descriptor if not applicable to macOS.
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
    """macOS periodic plugin.

    Parses information on daily, weekly and monthly system maintenance jobs.
    No longer in use since macOS Sequoia.

    References:
        - https://man.freebsd.org/cgi/man.cgi?periodic.conf
    """

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
        """Return macOS periodic script paths."""
        for file in self.periodic_scripts_files:
            yield PeriodicScriptsRecord(
                source=file,
            )

    @export(record=PeriodicConfRecords)
    def periodic_conf(self) -> Iterator[PeriodicConfRecords]:
        """Return macOS periodic configuration information.

        Yields the following record types extracted from the
        periodic.conf files:

        .. code-block:: text

            PeriodicConfRecord:
                local_periodic (string): List of directories to search for periodic scripts
                    when a non-absolute argument is passed to periodic(8).
                dir_output (string): Specifies how script output is handled; an absolute path
                    writes to a file, otherwise treated as email recipients.
                dir_show_success (boolean): Controls masking of output for scripts exiting with code 0.
                dir_show_info (boolean): Controls masking of output for scripts exiting with code 1.
                dir_show_badconfig (boolean): Controls masking of output for scripts exiting with code 2.
                anticongestion_sleeptime (varint): Maximum number of seconds to randomly sleep to reduce load bursts.
                source (path): Path to the periodic.conf file.

            PeriodicConfDailyRecord:
                daily_clean_disks_enable (boolean): Enables removal of files matching configured patterns.
                daily_clean_disks_files (string): List of filename patterns to match (wildcards allowed).
                daily_clean_disks_days (varint): File age in days required before deletion.
                daily_clean_disks_verbose (boolean): Reports removed files in output.
                daily_clean_tmps_enable (boolean): Enables cleanup of temporary directories.
                daily_clean_tmps_dirs (string): Directories to clean when enabled.
                daily_clean_tmps_days (varint): File age threshold before deletion.
                daily_clean_tmps_ignore (string): File patterns excluded from deletion.
                daily_clean_tmps_verbose (boolean): Reports removed temporary files.
                daily_clean_preserve_enable (boolean): Enables cleanup of /var/preserve.
                daily_clean_preserve_days (varint): File age threshold before deletion.
                daily_clean_preserve_verbose (boolean): Reports removed files.
                daily_clean_msgs_enable (boolean): Enables purging of old system messages.
                daily_clean_msgs_days (varint): Age threshold for message deletion.
                daily_clean_rwho_enable (boolean): Enables purging of files in /var/who.
                daily_clean_rwho_days (varint): File age threshold before deletion.
                daily_clean_rwho_verbose (boolean): Reports removed files.
                daily_clean_hoststat_enable (boolean): Runs sendmail host status cleanup.
                daily_backup_efi_enable (boolean): Enables backup of EFI System Partition.
                daily_backup_gmirror_enable (boolean): Enables backup of gmirror information.
                daily_backup_gmirror_verbose (boolean): Reports differences between backups.
                daily_backup_gpart_enable (boolean): Enables backup of partition tables and boot data.
                daily_backup_gpart_verbose (boolean): Reports differences in partition backups.
                daily_backup_passwd_enable (boolean): Enables backup and verification of passwd/group files.
                daily_backup_aliases_enable (boolean): Enables backup and reporting of mail aliases.
                daily_backup_zfs_enable (boolean): Enables backup of zfs-list and zpool-list output.
                daily_backup_zfs_list_flags (string): Arguments passed to zfs-list(8).
                daily_backup_zpool_list_flags (string): Arguments passed to zpool-list(8).
                daily_backup_zfs_props_enable (boolean): Enables backup of zfs-get and zpool-get output.
                daily_backup_zfs_get_flags (string): Arguments passed to zfs-get(8).
                daily_backup_zpool_get_flags (string): Arguments passed to zpool-get(8).
                daily_backup_zfs_verbose (boolean): Reports differences between ZFS backups.
                daily_calendar_enable (boolean): Runs calendar(1) daily.
                daily_accounting_enable (boolean): Enables rotation of process accounting files.
                daily_accounting_compress (boolean): Compresses accounting files with gzip.
                daily_accounting_save (varint): Number of accounting files retained.
                daily_accounting_flags (string): Arguments passed to sa(8) utility.
                daily_status_disks_enable (boolean): Enables disk status reporting (df and dump).
                daily_status_disks_df_flags (string): Arguments passed to df(1).
                daily_status_zfs_enable (boolean): Enables zpool status reporting.
                daily_status_zfs_zpool_list_enable (boolean): Enables zpool list output.
                daily_status_gmirror_enable (boolean): Enables gmirror status reporting.
                daily_status_graid3_enable (boolean): Enables graid3 status reporting.
                daily_status_gstripe_enable (boolean): Enables gstripe status reporting.
                daily_status_gconcat_enable (boolean): Enables gconcat status reporting.
                daily_status_mfi_enable (boolean): Enables mfi device status reporting.
                daily_status_network_enable (boolean): Enables network interface reporting.
                daily_status_network_netstat_flags (string): Arguments passed to netstat(1).
                daily_status_network_usedns (boolean): Enables DNS lookups in netstat output.
                daily_status_uptime_enable (boolean): Runs uptime(1) or ruptime(1).
                daily_status_mailq_enable (boolean): Enables mail queue reporting.
                daily_status_mailq_shorten (boolean): Produces abbreviated mail queue output.
                daily_status_include_submit_mailq (boolean): Includes submit queue in output.
                daily_status_security_enable (boolean): Enables execution of periodic security scripts.
                daily_status_security_inline (boolean): Outputs security results inline.
                daily_status_security_output (string): Destination for security output when not inline.
                daily_status_mail_rejects_enable (boolean): Summarises rejected mail entries.
                daily_status_mail_rejects_logs (varint): Number of maillog files inspected.
                daily_status_ntpd_enable (boolean): Enables NTP status check.
                daily_status_world_kernel (boolean): Checks kernel and userland consistency.
                daily_queuerun_enable (boolean): Runs mail queue at least once daily.
                daily_submit_queuerun (boolean): Runs submit mail queue when enabled.
                daily_scrub_zfs_enable (boolean): Enables periodic ZFS scrub.
                daily_scrub_zfs_pools (string): ZFS pools to scrub (defaults to all).
                daily_scrub_zfs_default_threshold (varint): Default number of days between scrubs.
                daily_trim_zfs_enable (boolean): Enables ZFS trim operation.
                daily_trim_zfs_pools (string): ZFS pools to trim (defaults to all).
                daily_local (string): Additional scripts executed after standard daily scripts.
                daily_diff_flags (string): Arguments passed to diff(1) for comparisons.
                source (path): Path to the periodic.conf file.

            PeriodicConfWeeklyRecord:
                weekly_locate_enable (boolean): Runs locate.updatedb to rebuild locate database.
                weekly_whatis_enable (boolean): Regenerates whatis database for apropos(1).
                weekly_noid_enable (boolean): Searches for files with invalid ownership.
                weekly_noid_dirs (string): Directories to scan for orphaned files.
                weekly_status_security_enable (boolean): Enables weekly security checks.
                weekly_status_security_inline (boolean): Outputs security results inline.
                weekly_status_security_output (string): Destination for security output.
                weekly_status_pkg_enable (boolean): Lists outdated installed packages.
                pkg_version (string): Program used to determine outdated packages.
                pkg_version_index (string): INDEX file used for package version comparison.
                weekly_local (string): Additional scripts executed after standard weekly scripts.
                source (path): Path to the periodic.conf file.

            PeriodicConfMonthlyRecord:
                monthly_accounting_enable (boolean): Enables login accounting using ac(8).
                monthly_status_security_enable (boolean): Enables monthly security checks.
                monthly_status_security_inline (boolean): Outputs security results inline.
                monthly_status_security_output (string): Destination for security output.
                monthly_local (string): Additional scripts executed after standard monthly scripts.
                source (path): Path to the periodic.conf file.

            PeriodicConfSecurityRecord:
                security_status_diff_flags (string): Arguments passed to diff(1) for comparisons.
                security_status_chksetuid_enable (boolean): Compares setuid file modes and timestamps.
                security_status_chksetuid_period (string): Frequency of execution.
                security_status_chkportsum_enable (boolean): Verifies installed package checksums.
                security_status_chkportsum_period (string): Frequency of execution.
                security_status_neggrpperm_enable (boolean): Checks for group permission inconsistencies.
                security_status_neggrpperm_period (string): Frequency of execution.
                security_status_chkmounts_enable (boolean): Compares mounted filesystem changes.
                security_status_chkmounts_period (string): Frequency of execution.
                security_status_noamd (boolean): Ignores amd mounts when comparing filesystems.
                security_status_chkuid0_enable (boolean): Checks for accounts with UID 0.
                security_status_chkuid0_period (string): Frequency of execution.
                security_status_passwdless_enable (boolean): Checks for accounts without passwords.
                security_status_passwdless_period (string): Frequency of execution.
                security_status_logincheck_enable (boolean): Checks ownership of /etc/login.conf.
                security_status_logincheck_period (string): Frequency of execution.
                security_status_ipfwdenied_enable (boolean): Reports packets denied by ipfw.
                security_status_ipfwdenied_period (string): Frequency of execution.
                security_status_ipfdenied_enable (boolean): Reports packets denied by ipf.
                security_status_ipfdenied_period (string): Frequency of execution.
                security_status_pfdenied_enable (boolean): Reports packets denied by pf.
                security_status_pfdenied_additionalanchors (string): Additional anchors to include.
                security_status_pfdenied_period (string): Frequency of execution.
                security_status_ipfwlimit_enable (boolean): Displays ipfw rules at limit.
                security_status_ipfwlimit_period (string): Frequency of execution.
                security_status_kernelmsg_enable (boolean): Shows new kernel messages (dmesg).
                security_status_kernelmsg_period (string): Frequency of execution.
                security_status_loginfail_enable (boolean): Reports failed login attempts.
                security_status_loginfail_period (string): Frequency of execution.
                security_status_tcpwrap_enable (boolean): Reports tcpwrapper denied connections.
                security_status_tcpwrap_period (string): Frequency of execution.
                source (path): Path to the periodic.conf file.
        """
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
