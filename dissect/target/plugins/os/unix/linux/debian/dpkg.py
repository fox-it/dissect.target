from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.os.unix.packagemanager import (
    PackageManagerLogRecord,
    PackageManagerPackageFileRecord,
    PackageManagerPackageRecord,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


class DpkgPlugin(Plugin):
    """Debian Package (dpkg) plugin.

    Does not currently parse ``*-old`` files.

    References:
        - https://wiki.debian.org/dpkg
    """

    __namespace__ = "dpkg"

    def __init__(self, target: Target):
        super().__init__(target)

        self.log_files = list(self.target.fs.path("/var/log/").glob("dpkg.log*"))
        self.info_list_files = list(target.fs.path("/var/lib/dpkg/info/").glob("*.list"))

        self.status_file = None
        if (status_file := self.target.fs.path("/var/lib/dpkg/status")).is_file():
            self.status_file = status_file

    def check_compatible(self) -> None:
        if not self.log_files and not self.info_list_files and not self.status_file:
            raise UnsupportedPluginError("No Debian package file(s) found on target")

    @export(record=[PackageManagerPackageRecord, PackageManagerPackageFileRecord])
    @arg("--output-files", action="store_true", help="output package file content records")
    def packages(
        self, output_files: bool = False
    ) -> Iterator[PackageManagerPackageRecord | PackageManagerPackageFileRecord]:
        """Yields information about installed Debian packages."""

        if not self.status_file:
            self.target.log.warning("No dpkg status file found on target")
            return

        for block in read_status_blocks(self.status_file.read_text()):
            package = parse_status_block(block)

            if not package.get("Package"):
                self.target.log.warning("Failed to parse package block in %s", self.status_file)
                continue

            if "installed" not in package.get("Status", ""):
                self.target.log.info("Encountered non-installed package: %s", package)
                continue

            name = package["Package"]
            version = package.get("Version", "")
            full_name = f"{name}-{version}".strip("-")

            if arch := package.get("Architecture", ""):
                full_name += f".{arch}"

            # See if we have a .list and .md5sums file for this package.
            files = {}
            for list_file in (f"/var/lib/dpkg/info/{name}.list", f"/var/lib/dpkg/info/{name}:{arch}.list"):
                if (list_path := self.target.fs.path(list_file)).is_file():
                    files = parse_list_file(list_path)
                    break

            ts = list_path.lstat().st_mtime if list_path.is_file() else None

            yield PackageManagerPackageRecord(
                ts=ts,
                package_manager="dpkg",
                package_name=name,
                package_name_full=full_name,
                package_version=version or None,
                package_release=version.split("-", maxsplit=1)[-1] or None,
                package_arch=package.get("Architecture"),
                package_vendor=package.get("Maintainer"),
                package_summary=package.get("Description"),
                package_size=package.get("Size"),
                package_archive=None,
                package_files=files.keys(),
                package_files_digests=[(digest, None, None) for digest in files.values() if digest],
                source=self.status_file,
                _target=self.target,
            )

            if output_files:
                for file, stored_digest in files.items():
                    actual_digest = file.get().hash(["md5"])[0] if file.is_file() else None

                    yield PackageManagerPackageFileRecord(
                        ts=ts,
                        package_manager="dpkg",
                        package_name=name,
                        package_name_full=full_name,
                        path=file,
                        exists=file.exists(),
                        stored_digest=(stored_digest, None, None),
                        actual_digest=(actual_digest, None, None),
                        digest_match=(stored_digest == actual_digest) if stored_digest else None,
                        source=list_path,
                        _target=self.target,
                    )

    @export(record=PackageManagerLogRecord)
    def logs(self) -> Iterator[PackageManagerLogRecord]:
        """Yield records for actions logged in dpkg's logs."""

        for log_file in self.log_files:
            for line in open_decompress(log_file, "rt"):
                if not (line := line.strip()):
                    continue

                try:
                    parsed_line = parse_log_line(line, self.target.datetime.tzinfo)
                except NotImplementedError:
                    continue
                except ValueError:
                    self.target.log.debug("Can not parse dpkg log line `%s`", line, exc_info=True)
                    continue

                yield PackageManagerLogRecord(
                    **parsed_line,
                    package_manager="dpkg",
                    source=log_file,
                    _target=self.target,
                )


def read_status_blocks(input: str) -> Iterator[list[str]]:
    """Yield package status blocks read from ``fh`` text stream as the lists of lines."""
    block_lines = []
    for line in input.split("\n"):
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


def parse_status_block(block_lines: list[str]) -> dict[str, str]:
    """Parse package details block from dpkg status file."""
    result = {}
    previous_key = None

    for line in block_lines:
        # Line can be part of previous value if it is indented.
        if line.startswith(" "):
            result[previous_key] += line
            continue

        key, _, value = line.partition(": ")
        previous_key = key
        result[key] = value.strip()

    return result


def parse_log_line(log_line: str, tzinfo: tzinfo = timezone.utc) -> dict[str, str]:
    """Parse a single dpkg log file line.

    Example status log line::
        2022-01-03 12:47:24 status unpacked python3.8:amd64 3.8.10-0ubuntu1~20.04.2

    Example install log line::
        2022-01-03 12:47:41 install linux-modules-extra-5.11.0-43-generic:amd64 <none> 5.11.0-43.47~20.04.2
    """

    parts = log_line.split(" ")

    # Skip lines that are not about operations on packages
    if len(parts) != 6:
        raise NotImplementedError

    log_date, log_time, operation = parts[:3]

    result = {
        "ts": datetime.strptime(f"{log_date} {log_time}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=tzinfo),
        "operation": operation,
        "message": " ".join(parts[2:]),
    }

    if operation == "status":
        _, package_arch, version = parts[3:]
        name, _, _ = package_arch.partition(":")
        result.update(
            {
                "package_name": name,
                "package_version": version,
            }
        )
        return result

    if operation in ("install", "upgrade", "remove", "trigproc"):
        package_arch, version_old, version = parts[3:]
        name, _, _ = package_arch.partition(":")
        version = None if version == "<none>" else version
        version_old = None if version_old == "<none>" else version_old
        result.update(
            {
                "package_name": name,
                "package_version": version,
            }
        )
        return result

    raise ValueError(f"Unrecognized operation `{operation}` in dpkg log file line: `{log_line}`")


def parse_list_file(list_path: Path) -> dict[Path, str | None]:
    """Returns dict of file paths and digests of files for the given list_file."""

    root = list_path.parents[-1]
    md5sums_path = list_path.with_suffix(".md5sums")
    map = {}

    if md5sums_path.is_file():
        for line in md5sums_path.open("rt"):
            if not (line := line.strip()):
                continue
            hexdigest, _, rel_path = line.partition("  ")
            map[root.joinpath(rel_path)] = hexdigest

    for line in list_path.open("rt"):
        if not (line := line.strip()) or line == "/.":
            continue
        path = root.joinpath(line)
        if path not in map:
            map[path] = None

    return map
