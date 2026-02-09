from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.configutil import Env
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

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


class EnvironmentFilePlugin(Plugin):
    """Environment file plugin."""

    def check_compatible(self) -> None:
        # `--env-path` is required at runtime
        pass

    @export(record=EnvironmentFileRecord)
    @arg("--env-path", required=True, help="path to scan environment files in")
    @arg("--extension", default="env", help="extension of files to scan")
    def envfile(self, env_path: str, extension: str = "env") -> Iterator[EnvironmentFileRecord]:
        """Yield environment variables found in ``.env`` files at the provided path."""

        if not env_path:
            self.target.log.error("No ``--path`` provided!")
            return

        if not (path := self.target.fs.path(env_path)).exists():
            self.target.log.error("Provided path %s does not exist!", path)
            return

        for file in path.glob("**/*." + extension):
            if not file.is_file():
                continue

            mtime = file.lstat().st_mtime

            with file.open("r") as fh:
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
