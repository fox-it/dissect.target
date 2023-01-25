import re
from datetime import datetime, timezone
from typing import Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.os.unix.log.packagemanagers.model import PackageManagerLogRecord, OperationTypes

APT_LOG_OPERATIONS = ["Install", "Reinstall", "Upgrade", "Downgrade", "Remove", "Purge"]


def generate_record(package_manager: str):
    return PackageManagerLogRecord(
        package_manager=package_manager,
        package_names="",
    )


class AptPlugin(plugin.Plugin):
    __namespace__ = "apt"
    LOGS_DIR_PATH = "/var/log/"
    LOGS_GLOB = "apt/history.*"

    def __init__(self, target):
        super().__init__(target)

        try:
            self.target_timezone = ZoneInfo(f"{target.timezone}")
        except ZoneInfoNotFoundError:
            self.target.log.warning("Could not determine timezone of target, falling back to UTC.")
            self.target_timezone = timezone.utc

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB):
            raise UnsupportedPluginError("No apt logs found")

    @staticmethod
    def parse_logs(log_lines: [str], tz: ZoneInfo) -> Iterator[PackageManagerLogRecord]:
        """
        A log parser for APT. Apt creates logs that are multiline and therefore requires somewhat complex parsing logic.
        We create one PackageManagerLogRecord per package and type; the example below hence generates *three* records.

        An example:

        Start-Date: 2022-09-21  06:48:56
        Commandline: /usr/bin/unattended-upgrade
        Install: linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic),
        Upgrade: linux-headers-generic:amd64 (5.4.0.125.126, 5.4.0.126.127), libpython3.9-minimal:amd64 (3.9.5-3ubuntu0~20.04.1, automatic)  # noqa
        Requested-By: user (1000)
        End-Date: 2022-09-21  06:48:57
        """  # noqa E501

        log_lines.append("")
        chunk = []

        for line in log_lines:
            if line != "":
                chunk.append(line)
            else:
                # indicates the end of a log chunk; which we will need to split into separate records
                records = split_into_records(chunk, tz)
                for record in records:
                    yield record

                chunk = []

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self):
        log_file_paths = self.target.fs.path(self.LOGS_DIR_PATH).glob(self.LOGS_GLOB)

        for path in log_file_paths:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]

            yield from self.parse_logs(log_lines, self.target_timezone)


def split_package_names(package_names: str) -> list[str]:
    """
    package_names contains the names of multiple packages, separated by a comma
        linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic),
        linux-headers-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-modules-extra-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-modules-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-image-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic)
    returns a list of strings: ['linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic)', ...]
    """  # noqa E501
    REGEX = r"(.*?\)),?"
    package_names = re.findall(REGEX, package_names)
    return [name.strip() for name in package_names]


def split_into_records(chunk: [str], tz: ZoneInfo) -> [PackageManagerLogRecord]:
    packages = []
    ts = user = command = None

    # we parse the chunk line for line and try to extract as much information from each line as possible
    for line in chunk:
        if any(log_type in line for log_type in APT_LOG_OPERATIONS):
            operation, package_names = line.split(": ")
            package_names = split_package_names(package_names)

            for name in package_names:
                packages.append((operation, name))

        elif line.startswith("Start-Date"):
            dt_string = line.split("Start-Date: ")[1]
            ts = datetime.strptime(dt_string, "%Y-%m-%d  %H:%M:%S")
            ts.replace(tzinfo=tz)

        elif line.startswith("Requested-By"):
            user = line.split("Requested-By: ")[1]

        elif line.startswith("Commandline: "):
            command = line.split("Commandline: ")[1]

    for operation, name in packages:
        operation = OperationTypes.infer(operation)

        yield PackageManagerLogRecord(
            ts=ts,
            package_manager="apt",
            package_name=name,
            operation=operation.value,
            user=user,
            command=command,
        )
