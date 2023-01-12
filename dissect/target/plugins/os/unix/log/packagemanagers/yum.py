from datetime import datetime
from typing import Iterator

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, decompress_and_readlines
from dissect.target.plugins.os.unix.log.packagemanagers.model import PackageManagerLogRecord, OperationTypes

YUM_LOG_KEYWORDS = ["Installed", "Updated", "Erased", "Obsoleted"]


class YumPlugin(plugin.Plugin):
    __namespace__ = "yum"
    LOGS_DIR_PATH = "/var/log/"
    LOGS_GLOB = "yum.*"

    def __init__(self, target):
        super().__init__(target)

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB):
            raise UnsupportedPluginError("No yum logs found")

    def parse_logs(self, log_lines: [str], filepath: TargetPath) -> Iterator[PackageManagerLogRecord]:
        """
        Logs are formatted like this:
            Dec 16 04:41:22 Installed: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:25 Installed: unzip-6.0-22.el7_9.x86_64
            Dec 16 04:41:28 Updated: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:30 Erased: unzip-6.0-24.el7_9.x86_64
            Dec 16 04:41:34 Installed: unzip-6.0-24.el7_9.x86_64
        """

        for line in log_lines:
            # only parse lines that are about installation/erasions/updates, not empty lines or debug statements
            if not any(keyword in line for keyword in YUM_LOG_KEYWORDS):
                continue

            # TODO: how should we deal with logs that span multiple years?
            file_mtime = self.target.fs.get(str(filepath)).stat().st_mtime
            year_file_modified = datetime.fromtimestamp(file_mtime).year

            ts = datetime.strptime(line[0:15], "%b %d %H:%M:%S")
            ts = ts.replace(year=year_file_modified)

            message = line[16:]
            operation, package_name = message.split(": ")
            operation = OperationTypes.infer(operation.strip())

            yield PackageManagerLogRecord(
                package_manager="yum", ts=ts, operation=operation.value, package_name=package_name
            )

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self):
        log_file_paths = self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB)

        for path in log_file_paths:
            log_lines = [line.strip() for line in decompress_and_readlines(path)]

            yield from self.parse_logs(log_lines, path)
