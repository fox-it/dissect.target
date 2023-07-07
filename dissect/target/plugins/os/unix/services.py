import re
from itertools import chain
from typing import BinaryIO, Iterator

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

    def check_compatible(self):
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

            for file_ in path.iterdir():
                if should_ignore_file(file_.name, ignored_suffixes):
                    continue

                try:
                    fh = file_.open("rt")
                except FileNotFoundError:
                    # The service is registered but the symlink is broken.
                    yield LinuxServiceRecord(
                        ts=file_.stat(follow_symlinks=False).st_mtime,
                        name=file_.name,
                        config=None,
                        source=file_,
                        _target=self.target,
                    )
                    continue

                config = parse_systemd_config(fh)

                yield LinuxServiceRecord(
                    ts=file_.stat().st_mtime,
                    name=file_.name,
                    config=config,
                    source=file_,
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


def parse_systemd_config(fh: BinaryIO) -> str:
    """Returns a string of key/value pairs from a toml/ini-like string.

    This should probably be rewritten to return a proper dict as in
    its current form this is only useful when used in Splunk.
    """
    variables = ""

    try:
        for line in fh:
            line = line.strip().replace("\n", "")

            # segment start eg. [ExampleSegment]
            if line[:1] == "[":
                segment = re.sub(r"\[|\]", "", line)

            # ignore comments and empty lines
            elif line[:1] == ";" or line[:1] == "#" or line == "":
                continue

            # if line ends with \ it is likely part of a multi-line command argument
            elif line[-1] == "\\" or line[-1] == "'":
                variables = f"{variables} {line} "

            else:
                line = line.split("=", 1)
                if "segment" in locals():
                    # some variables/arguments are not delimited by a '='
                    # (eg. '-Kvalue' instead of '-key=value')
                    if len(line) < 2:
                        variables = f"{variables} {segment}_{line[0]} "
                    else:
                        variables = f'{variables} {segment}_{line[0]}="{line[1]}" '
                else:
                    variables = f"{variables} {line} ".strip()

    except UnicodeDecodeError:
        pass

    return variables.strip()
