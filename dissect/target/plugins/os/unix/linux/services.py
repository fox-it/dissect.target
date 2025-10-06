from __future__ import annotations

from itertools import chain
from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

RECORD_NAME = "linux/service"

DEFAULT_ELEMENTS = [
    ("datetime", "ts"),
    ("string", "type"),
    ("string", "name"),
    ("path", "source"),
]

LinuxServiceRecord = TargetRecordDescriptor(RECORD_NAME, DEFAULT_ELEMENTS)


class ServicesPlugin(Plugin):
    """Linux services plugin."""

    SYSTEMD_PATHS = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )

    INITD_PATHS = ("/etc/rc.d/init.d", "/etc/init.d")

    def check_compatible(self) -> None:
        if not any(self.target.fs.path(p).exists() for p in self.SYSTEMD_PATHS + self.INITD_PATHS):
            raise UnsupportedPluginError("No supported service directories found")

    @export(record=LinuxServiceRecord)
    def services(self) -> Iterator[LinuxServiceRecord]:
        """Return information about all installed systemd and init.d services.

        References:
            - https://geeksforgeeks.org/what-is-init-d-in-linux-service-management
            - http://0pointer.de/blog/projects/systemd-for-admins-3.html
            - https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html
        """

        return chain(self.systemd(), self.initd())

    @internal
    def systemd(self) -> Iterator[LinuxServiceRecord]:
        ignored_suffixes = [".wants", ".requires", ".d"]

        for systemd_path in self.SYSTEMD_PATHS:
            path = self.target.fs.path(systemd_path)
            if not path.exists() or not path.is_dir():
                continue

            for service_file in path.iterdir():
                if should_ignore_file(service_file.name, ignored_suffixes):
                    continue

                config = {}
                types = []

                try:
                    for segment, configuration in configutil.parse(service_file, hint="systemd").items():
                        if not configuration:
                            continue

                        if not isinstance(configuration, list):
                            configuration = [configuration]

                        for nested_conf in configuration:
                            for key, value in nested_conf.items():
                                _key = f"{segment}_{key}".replace("-", "_")

                                if _key not in config:
                                    config.update({_key: value or None})
                                else:
                                    if not isinstance(config[_key], list):
                                        config[_key] = [config[_key]]
                                    config[_key].append(value or None)

                                if isinstance(config[_key], list):
                                    types.append(("string[]", _key))
                                else:
                                    types.append(("string", _key))

                except FileNotFoundError:
                    # The service is registered but the symlink is broken.
                    yield LinuxServiceRecord(
                        ts=service_file.stat(follow_symlinks=False).st_mtime,
                        type="systemd",
                        name=service_file.name,
                        source=service_file,
                        _target=self.target,
                    )
                    continue

                record = TargetRecordDescriptor(RECORD_NAME, DEFAULT_ELEMENTS + types)
                yield record(
                    ts=service_file.stat().st_mtime,
                    type="systemd",
                    name=service_file.name,
                    source=service_file,
                    **config,
                    _target=self.target,
                )

    @internal
    def initd(self) -> Iterator[LinuxServiceRecord]:
        ignored_suffixes = ["README"]

        for initd_path in self.INITD_PATHS:
            path = self.target.fs.path(initd_path)

            if not path.exists():
                continue
            for file_ in path.iterdir():
                if should_ignore_file(file_.name, ignored_suffixes):
                    continue

                yield LinuxServiceRecord(
                    ts=file_.stat().st_mtime,
                    type="initd",
                    name=file_.name,
                    source=file_,
                    _target=self.target,
                )


def should_ignore_file(needle: str, haystack: list) -> bool:
    return needle.endswith(tuple(haystack))
