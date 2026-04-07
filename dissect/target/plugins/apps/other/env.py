from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.configutil import Env
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator

EnvironmentFileRecord = TargetRecordDescriptor(
    "application/other/file/environment",
    [
        ("datetime", "ts_mtime"),
        ("string", "key"),
        ("string", "value"),
        ("string", "comment"),
        ("path", "path"),
    ],
)


@arg("--path", required=True, help="path to scan environment files in")
@arg("--extension", default="env", help="extension of files to scan")
class EnvironmentFilePlugin(Plugin):
    """Environment file plugin."""

    def __init__(self, target: Target):
        super().__init__(target)

        args = self.get_args()
        self.path = args.path
        self.extension = args.extension
        self.files: list[Path] = []

        if args.path and (dir := self.target.fs.path(args.path)).is_dir():
            self.files.extend(path for path in dir.glob(f"**/*.{args.extension}"))

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError(f"No environment variable files found in {self.path}/**/*.{self.extension}")

    @export(record=EnvironmentFileRecord)
    def envfile(self) -> Iterator[EnvironmentFileRecord]:
        """Yield environment variables found in ``.env`` files at the provided path."""
        for file in self.files:
            if not file.is_file():
                continue

            mtime = file.lstat().st_mtime

            with file.open("rt") as fh:
                parser = Env(comments=True)
                parser.read_file(fh)

                for key, (value, comment) in parser.parsed_data.items():
                    yield EnvironmentFileRecord(
                        ts_mtime=mtime,
                        key=key,
                        value=value,
                        comment=comment,
                        path=file,
                        _target=self.target,
                    )
