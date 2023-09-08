import itertools
import re
from datetime import datetime
from typing import Iterator
from zoneinfo import ZoneInfo

from dissect.target import Target, plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.os.unix.packagemanager import (
    OperationTypes,
    PackageManagerLogRecord,
)

APT_LOG_OPERATIONS = ["Install", "Reinstall", "Upgrade", "Downgrade", "Remove", "Purge"]
REGEX_PACKAGE_NAMES = re.compile(r"(.*?\)),?")


class AptPlugin(plugin.Plugin):
    __namespace__ = "apt"

    LOG_DIR_PATH = "/var/log/apt"
    LOG_FILES_GLOB = "history.*"

    def check_compatible(self) -> None:
        log_files = list(self.target.fs.path(self.LOG_DIR_PATH).glob(self.LOG_FILES_GLOB))
        if not len(log_files):
            raise UnsupportedPluginError("No APT files found")

    @plugin.export(record=PackageManagerLogRecord)
    def logs(self) -> Iterator[PackageManagerLogRecord]:
        """Package manager log parser for Apt.

        Apt creates logs that are multiline and therefore requires somewhat complex parsing logic.
        We create one ``PackageManagerLogRecord`` per package and type; the example below hence generates *three* records.

        Example log format::

            Start-Date: 2022-09-21  06:48:56
            Commandline: /usr/bin/unattended-upgrade
            Install: linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic),
            Upgrade: linux-headers-generic:amd64 (5.4.0.125.126, 5.4.0.126.127), libpython3.9-minimal:amd64 (3.9.5-3ubuntu0~20.04.1, automatic)
            Requested-By: user (1000)
            End-Date: 2022-09-21  06:48:57
        """  # noqa E501

        tzinfo = self.target.datetime.tzinfo
        for path in self.target.fs.path(self.LOG_DIR_PATH).glob(self.LOG_FILES_GLOB):
            chunk = []
            for line in itertools.chain(open_decompress(path, "rt"), [""]):
                line = line.strip()

                # Indicates the end of a log chunk
                if line == "":
                    yield from split_into_records(chunk, tzinfo, self.target)
                    chunk = []
                    continue

                chunk.append(line)


def split_into_records(chunk: Iterator[str], tz: ZoneInfo, target: Target) -> Iterator[PackageManagerLogRecord]:
    """Parse the chunk line for line and try to extract as much information from each line as possible."""
    packages = []
    ts = None
    user = None
    command = None

    for line in chunk:
        if any(log_type in line for log_type in APT_LOG_OPERATIONS):
            operation, package_names = line.split(": ")
            package_names = split_package_names(package_names)

            for name in package_names:
                packages.append((operation, name))

        elif line.startswith("Start-Date"):
            dt_string = line.split("Start-Date: ")[1]
            ts = datetime.strptime(dt_string, "%Y-%m-%d  %H:%M:%S").replace(tzinfo=tz)

        elif line.startswith("Requested-By"):
            user = line.split("Requested-By: ")[1]

        elif line.startswith("Commandline: "):
            command = line.split("Commandline: ")[1]

    for operation, name in packages:
        yield PackageManagerLogRecord(
            ts=ts,
            package_manager="apt",
            package_name=name,
            operation=OperationTypes.infer(operation).value,
            requested_by_user=user,
            command=command,
            _target=target,
        )


def split_package_names(package_names: str) -> list[str]:
    """Splits a comma separated list of package names.

    Example ``package_names``::

        linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic),
        linux-headers-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-modules-extra-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-modules-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic),
        linux-image-5.4.0-126-generic:amd64 (5.4.0-126.142, automatic)

    Returns:
        A list of package names, e.g. ``['linux-headers-5.4.0-126:amd64 (5.4.0-126.142, automatic)', ...]``
    """  # noqa E501

    package_names = REGEX_PACKAGE_NAMES.findall(package_names)
    return [name.strip() for name in package_names]
