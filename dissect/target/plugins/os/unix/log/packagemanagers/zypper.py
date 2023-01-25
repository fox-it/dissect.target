from datetime import datetime, timezone
from typing import Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.os.unix.log.packagemanagers.model import PackageManagerLogRecord, OperationTypes


class ZypperPlugin(plugin.Plugin):
    __namespace__ = "zypper"
    LOGS_DIR_PATH = "/var/log/"
    LOGS_GLOB = "zypp/history*"

    def __init__(self, target):
        super().__init__(target)

        try:
            self.target_timezone = ZoneInfo(f"{target.timezone}")
        except ZoneInfoNotFoundError:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC.")
            self.target_timezone = timezone.utc

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB):
            raise UnsupportedPluginError("No zypper logs found")

    @staticmethod
    def parse_logs(log_lines: [str], tz: ZoneInfo) -> Iterator[PackageManagerLogRecord]:
        """
        Logs are formatted like this:
            2022-12-16 12:56:23|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
            2022-12-16 12:56:23|install|update-alternatives|1.21.8-1.4|x86_64||repo-oss|b4d6389437e306d6104559c82d09fce15c4486fbc7fd215cc33d265ff729aaf1|  # noqa
            # 2022-12-16 12:56:23 unzip-6.00-41.1.x86_64.rpm installed ok
            # Additional rpm output:
            # update-alternatives: using /usr/bin/unzip-plain to provide /usr/bin/unzip (unzip) in auto mode
            #
            2022-12-16 12:56:23|install|unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|repo-oss|d7e42c9d83f97cf3b7eceb4d3fa64e445a33a7a33f387366734c444d5571cb3a|  # noqa
            2022-12-16 12:57:50|command|root@ec9fa6d67dda|'zypper' 'remove' 'unzip'|
            # 2022-12-16 12:57:50 unzip-6.00-41.1.x86_64 removed ok
            # Additional rpm output:
            # update-alternatives: warning: alternative /usr/bin/unzipsfx-plain (part of link group unzipsfx) doesn't exist; removing from list of alternatives  # noqa
            # update-alternatives: warning: alternative /usr/bin/zipgrep-plain (part of link group zipgrep) doesn't exist; removing from list of alternatives  # noqa
            #
            2022-12-16 12:57:50|remove |unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|
            2022-12-16 12:58:49|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
        """  # noqa E501

        for line in log_lines:
            # we don't parse additional output logs or empty logs
            if line.startswith("#") or line == "":
                continue

            ts, operation, *log_arguments = line.split("|")
            ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
            operation = OperationTypes.infer(operation)

            record = PackageManagerLogRecord(package_manager="zypper", ts=ts, operation=operation.value)

            if operation == OperationTypes.Install:
                yield parse_install_line(log_arguments, record)
            elif operation == OperationTypes.Remove:
                yield parse_remove_line(log_arguments, record)
            elif operation == OperationTypes.Other:
                yield parse_command_line(log_arguments, record)

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self):
        log_file_paths = self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB)

        for path in log_file_paths:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]

            yield from self.parse_logs(log_lines, self.target_timezone)


def parse_command_line(line: [str], record: PackageManagerLogRecord) -> PackageManagerLogRecord:
    """
    Receives: 2022-12-16 12:56:23|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
    Returns: <linux/log/package_manager hostname=None domain=None package_manager='zypper'
                ts=2022-12-16 12:57:50 package_name=None command='zypper install unzip' user='root@ec9fa6d67dda'>
    """
    user, command, *_ = line
    record.user = user

    command = command.replace("'", "")
    record.command = command
    return record


def parse_install_line(line: [str], record: PackageManagerLogRecord) -> PackageManagerLogRecord:
    """
    Receives: 2022-12-16 12:56:23|install|update-alternatives|1.21.8-1.4|x86_64||repo-oss|b4d6389437e306d6104559c82d09fce15c4486fbc7fd215cc33d265ff729aaf1|  # noqa
    Returns: <linux/log/package_manager hostname=None domain=None package_manager='zypper' ts=2022-12-16 12:56:23
                package_name='update-alternatives-1.21.8-1.4.x86_64' command=None user=None>
    """  # noqa E501
    package_name, version, arch, *_ = line
    record.package_name = f"{package_name}-{version}:{arch}"
    return record


def parse_remove_line(line: [str], record: PackageManagerLogRecord) -> PackageManagerLogRecord:
    """
    Receives: 2022-12-16 12:57:50|remove |unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|
    Returns: <linux/log/package_manager hostname=None domain=None package_manager='zypper' ts=2022-12-16 12:56:23
                package_name='update-alternatives-1.21.8-1.4.x86_64' command=None user=None>
    """
    package_name, version, arch, user, *_ = line
    record.package_name = f"{package_name}-{version}:{arch}"
    record.user = user
    return record
