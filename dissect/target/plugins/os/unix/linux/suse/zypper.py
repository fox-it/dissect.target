from datetime import datetime
from typing import Iterator

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.os.unix.packagemanager import (
    OperationTypes,
    PackageManagerLogRecord,
)


class ZypperPlugin(plugin.Plugin):
    __namespace__ = "zypper"

    LOG_DIR_PATH = "/var/log/zypp"
    LOG_FILES_GLOB = "history*"

    def check_compatible(self) -> None:
        log_files = list(self.target.fs.path(self.LOG_DIR_PATH).glob(self.LOG_FILES_GLOB))
        if not len(log_files):
            raise UnsupportedPluginError("No zypper files found")

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self) -> Iterator[PackageManagerLogRecord]:
        """Package manager log parser for SuSE's Zypper.

        Example log format::

            2022-12-16 12:56:23|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
            2022-12-16 12:56:23|install|update-alternatives|1.21.8-1.4|x86_64||repo-oss|b4d6389437e306d6104559c82d09fce15c4486fbc7fd215cc33d265ff729aaf1|
            # 2022-12-16 12:56:23 unzip-6.00-41.1.x86_64.rpm installed ok
            # Additional rpm output:
            # update-alternatives: using /usr/bin/unzip-plain to provide /usr/bin/unzip (unzip) in auto mode
            #
            2022-12-16 12:56:23|install|unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|repo-oss|d7e42c9d83f97cf3b7eceb4d3fa64e445a33a7a33f387366734c444d5571cb3a|
            2022-12-16 12:57:50|command|root@ec9fa6d67dda|'zypper' 'remove' 'unzip'|
            # 2022-12-16 12:57:50 unzip-6.00-41.1.x86_64 removed ok
            # Additional rpm output:
            # update-alternatives: warning: alternative /usr/bin/unzipsfx-plain (part of link group unzipsfx) doesn't exist; removing from list of alternatives
            # update-alternatives: warning: alternative /usr/bin/zipgrep-plain (part of link group zipgrep) doesn't exist; removing from list of alternatives
            #
            2022-12-16 12:57:50|remove |unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|
            2022-12-16 12:58:49|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
        """  # noqa E501

        tzinfo = self.target.datetime.tzinfo
        for path in self.target.fs.path(self.LOG_DIR_PATH).glob(self.LOG_FILES_GLOB):
            for line in open_decompress(path, "rt"):
                line = line.strip()

                # We don't parse additional output logs (#) or empty lines
                if not line or line.startswith("#"):
                    continue

                ts, operation, *remainder = line.split("|")
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tzinfo)
                operation = OperationTypes.infer(operation)

                record = PackageManagerLogRecord(
                    ts=ts,
                    package_manager="zypper",
                    operation=operation.value,
                    _target=self.target,
                )

                if operation == OperationTypes.Install:
                    # 2022-12-16 12:56:23|install|update-alternatives|1.21.8-1.4|x86_64||repo-oss|b4d6389437e306d6104559c82d09fce15c4486fbc7fd215cc33d265ff729aaf1|  # noqa E501
                    package_name, version, arch, *_ = remainder
                    record.package_name = f"{package_name}-{version}:{arch}"
                elif operation == OperationTypes.Remove:
                    # 2022-12-16 12:57:50|remove |unzip|6.00-41.1|x86_64|root@ec9fa6d67dda|
                    package_name, version, arch, user, *_ = remainder
                    record.package_name = f"{package_name}-{version}:{arch}"
                    record.requested_by_user = user.split("@")[0]
                elif operation == OperationTypes.Other:
                    # 2022-12-16 12:56:23|command|root@ec9fa6d67dda|'zypper' 'install' 'unzip'|
                    user, command, *_ = remainder
                    record.requested_by_user = user.split("@")[0]
                    record.command = command.replace("'", "")

                yield record
