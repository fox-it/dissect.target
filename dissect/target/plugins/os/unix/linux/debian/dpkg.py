import gzip
from datetime import datetime
from typing import Dict, Generator, List, TextIO

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

STATUS_FILE_NAME = "/var/lib/dpkg/status"
LOG_FILES_GLOB = "/var/log/dpkg.log*"

STATUS_FIELD_MAPPINGS = {
    "Package": "name",
    "Status": "status",
    "Priority": "priority",
    "Section": "section",
    "Architecture": "arch",
    "Version": "version",
}

STATUS_FIELDS_TO_EXTRACT = STATUS_FIELD_MAPPINGS.keys()

DpkgPackageStatusRecord = TargetRecordDescriptor(
    "linux/debian/dpkg/package/status",
    [
        ("string", "name"),
        ("string", "status"),
        ("string", "priority"),
        ("string", "section"),
        ("string", "arch"),
        ("string", "version"),
    ],
)

DpkgPackageLogRecord = TargetRecordDescriptor(
    "linux/debian/dpkg/package/log",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "operation"),
        ("string", "status"),
        ("string", "version_old"),
        ("string", "version"),
        ("string", "arch"),
    ],
)


class DpkgPlugin(Plugin):
    """
    Returns records for package details extracted from dpkg's status and log files.
    """

    __namespace__ = "dpkg"

    def check_compatible(self):
        log_files = list(self.target.fs.glob(LOG_FILES_GLOB))
        return len(log_files) > 0 or self.target.fs.path(STATUS_FILE_NAME).exists()

    @export(record=DpkgPackageStatusRecord)
    def status(self):
        """Yield records for packages in dpkg's status database"""

        status_file_path = self.target.fs.path(STATUS_FILE_NAME)

        if not status_file_path.exists():
            return

        for block_lines in read_status_blocks(status_file_path.open("rt")):
            details = parse_status_block(block_lines)

            if not details or not details.get("Package"):
                continue

            record_fields = {
                STATUS_FIELD_MAPPINGS[field]: value
                for field, value in details.items()
                if field in STATUS_FIELD_MAPPINGS
            }

            yield DpkgPackageStatusRecord(_target=self.target, **record_fields)

    @export(record=DpkgPackageLogRecord)
    def log(self):
        """Yield records for actions logged in dpkg's logs"""

        for log_file in self.target.fs.glob(LOG_FILES_GLOB):
            fh = self.target.fs.open(log_file)
            if log_file.lower().endswith(".gz"):
                fh = gzip.open(fh)

            for line in fh:
                line = line.decode("utf-8").strip()

                try:
                    parsed_line = parse_log_line(line)
                except ValueError:
                    self.target.log.debug("Can not parse dpkg log line `%s`", line, exc_info=True)
                    continue

                if not parsed_line:
                    continue

                yield DpkgPackageLogRecord(_target=self.target, **parsed_line)


def read_status_blocks(fh: TextIO) -> Generator[List[str], None, None]:
    """Yield package status blocks read from `fh` text stream as the lists of lines"""
    block_lines = []
    for line in fh:
        line = line.strip()

        # Package details blocks are separated by an empty line
        if not line:
            if block_lines:
                yield block_lines
                block_lines = []
            continue

        block_lines.append(line)

    if block_lines:
        yield block_lines


def parse_status_block(block_lines: List[str]) -> Dict[str, str]:
    """Parse package details block from dpkg status file"""
    result = {}
    for line in block_lines:
        field_name, _, value = line.partition(": ")
        if field_name in STATUS_FIELDS_TO_EXTRACT:
            result[field_name] = value.strip()
    return result


def parse_log_date_time(date_str: str, time_str: str) -> datetime:
    return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")


def parse_log_line(log_line: str) -> Dict[str, str]:
    """Parse dpkg log file line"""

    parts = log_line.split(" ")

    # Skip lines that are not about operations on packages
    if len(parts) != 6:
        return None

    result = {}
    log_date, log_time, operation = parts[:3]

    result = {
        "ts": parse_log_date_time(log_date, log_time),
        "operation": operation,
    }

    if operation == "status":
        # Example:
        # 2022-01-03 12:47:24 status unpacked python3.8:amd64 3.8.10-0ubuntu1~20.04.2

        status, package_arch, version = parts[3:]
        name, _, arch = package_arch.partition(":")
        result.update(
            {
                "name": name,
                "status": status,
                "arch": arch,
                "version": version,
            }
        )
    elif operation in ("install", "upgrade", "remove", "trigproc"):
        # Example:
        # 2022-01-03 12:47:41 install linux-modules-extra-5.11.0-43-generic:amd64 <none> 5.11.0-43.47~20.04.2
        package_arch, version_old, version = parts[3:]
        name, _, arch = package_arch.partition(":")
        version = None if version == "<none>" else version
        version_old = None if version_old == "<none>" else version_old
        result.update(
            {
                "name": name,
                "arch": arch,
                "version": version,
                "version_old": version_old,
            }
        )
    else:
        raise ValueError(f"Unrecognized operation `{operation}` in dpkg log file line: `{log_line}`")

    return result
