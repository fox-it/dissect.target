from itertools import chain
from typing import Iterator

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

LinuxServiceRecord = TargetRecordDescriptor(
    "linux/service",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "config"),
        ("path", "source"),
    ],
)


class ServicesPlugin(Plugin):
    SYSTEMD_PATHS = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]

    INITD_PATHS = ["/etc/rc.d/init.d", "/etc/init.d"]

    def check_compatible(self) -> None:
        if not any([self.target.fs.path(p).exists() for p in self.SYSTEMD_PATHS + self.INITD_PATHS]):
            raise UnsupportedPluginError("No supported service directories found")

    @export(record=LinuxServiceRecord)
    def services(self) -> Iterator[LinuxServiceRecord]:
        """Return information about all installed systemd and init.d services.

        References:
        - https://geeksforgeeks.org/what-is-init-d-in-linux-service-management
        - http://0pointer.de/blog/projects/systemd-for-admins-3.html
        - https://www.freedesktop.org/software/systemd/man/systemd.syntax.html
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

                try:
                    parsed_file = self.target.config_tree(service_file, as_dict=True)
                    config = create_systemd_string(parsed_file)
                except FileNotFoundError:
                    # The service is registered but the symlink is broken.
                    yield LinuxServiceRecord(
                        ts=service_file.stat(follow_symlinks=False).st_mtime,
                        name=service_file.name,
                        config=None,
                        source=service_file,
                        _target=self.target,
                    )
                    continue

                yield LinuxServiceRecord(
                    ts=service_file.stat().st_mtime,
                    name=service_file.name,
                    config=config,
                    source=service_file,
                    _target=self.target,
                )

    @internal
    def initd(self) -> Iterator[LinuxServiceRecord]:
        ignored_suffixes = ["README"]

        for initd_path in self.INITD_PATHS:
            path = self.target.fs.path(initd_path)

            if path.exists():
                for file_ in path.iterdir():
                    if should_ignore_file(file_.name, ignored_suffixes):
                        continue

                    yield LinuxServiceRecord(
                        ts=file_.stat().st_mtime,
                        name=file_.name,
                        config=None,
                        source=file_,
                        _target=self.target,
                    )


def should_ignore_file(needle: str, haystack: list) -> bool:
    for stray in haystack:
        if needle.endswith(stray):
            return True
    return False


def create_systemd_string(parsed_systemd_dict: dict[str, dict]) -> str:
    """Returns a string of key/value pairs from a toml/ini-like string.

    This should probably be rewritten to return a proper dict as in
    its current form this is only useful when used in Splunk.
    """

    output = []
    try:
        for segment, configuration in parsed_systemd_dict.items():
            for key, value in configuration.items():
                output.append(f'{segment}_{key}="{value}"')

    except UnicodeDecodeError:
        pass
    return " ".join(output)
