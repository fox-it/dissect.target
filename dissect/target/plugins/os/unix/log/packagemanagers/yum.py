import re
from typing import Iterator

from dissect.target import plugin
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugins.os.unix.log.packagemanagers.model import (
    OperationTypes,
    PackageManagerLogRecord,
)

YUM_LOG_KEYWORDS = ["Installed", "Updated", "Erased", "Obsoleted"]
RE_TS = re.compile(r"(\w+\s{1,2}\d+\s\d{2}:\d{2}:\d{2})")


class YumPlugin(plugin.Plugin):
    __namespace__ = "yum"

    def __init__(self, target):
        super().__init__(target)

        self.LOGS_DIR_PATH = "/var/log/"
        self.LOGS_GLOB = "yum.*"

    def check_compatible(self):
        return len(list(self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB))) > 0

    # def parse_line(self, ts: datetime, line: str) :

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self) -> Iterator[PackageManagerLogRecord]:
        """
        A package manager log parser for CentOS' Yellowdog Updater (Yum).

        Logs are formatted like this:
            Dec 16 04:41:22 Installed: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:25 Installed: unzip-6.0-22.el7_9.x86_64
            Dec 16 04:41:28 Updated: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:30 Erased: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:34 Installed: unzip-6.0-24.el7_9.x86_64
        """

        tzinfo = self.target.datetime.tzinfo
        log_files = self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB)

        for log_file in log_files:
            for ts, line in year_rollover_helper(log_file, RE_TS, "%b %d %H:%M:%S", tzinfo):
                # Only parse lines that are about installation/erasions/updates, not empty lines or debug statements.
                if not any(keyword in line for keyword in YUM_LOG_KEYWORDS):
                    return

                operation, package_name = line.split(": ")
                operation = OperationTypes.infer(operation.strip())

                yield PackageManagerLogRecord(
                    ts=ts,
                    package_manager="yum",
                    operation=operation.value,
                    package_name=package_name,
                    _target=self.target,
                )
