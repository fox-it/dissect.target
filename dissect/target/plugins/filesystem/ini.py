from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator


WindowsIniRecord = TargetRecordDescriptor(
    "filesystem/windows/ini",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("datetime", "btime"),
        ("string", "section"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class IniPlugin(Plugin):
    """INI file plugin."""

    def check_compatible(self) -> None:
        if not len(self.target.fs.mounts):
            raise UnsupportedPluginError("No filesystems found on target")

    def _iter_ini_files(self, path: str) -> Iterator:
        target_path = self.target.fs.path(path)
        if not target_path.exists():
            self.target.log.error("Provided path %s does not exist on target", target_path)
            return

        yield from target_path.rglob("*.ini")

    @export(record=WindowsIniRecord)
    @arg("-p", "--path", default="/", help="path to an .ini file or directory in target")
    def ini(self, path: str = "/") -> Iterator[WindowsIniRecord]:
        sources = self._iter_ini_files(path)

        for source in sources:
            try:
                config = configutil.parse(source, hint="ini")
                stat = source.stat()
            except FileNotFoundError as e:
                # File may disappear between compatibility check and parse.
                self.target.log.warning("File not found: %s", source)
                self.target.log.debug("", exc_info=e)
                continue
            except Exception as e:
                self.target.log.warning("Exception generating ini record for %s: %s", source, e)
                self.target.log.debug("", exc_info=e)
                continue

            for section_name in config:
                section = config.get(section_name)
                if section is None:
                    continue

                for key, value in section.items():
                    yield WindowsIniRecord(
                        atime=stat.st_atime,
                        mtime=stat.st_mtime,
                        ctime=stat.st_ctime,
                        btime=stat.st_birthtime,
                        section=section_name,
                        key=key,
                        value="" if value is None else str(value),
                        source=source,
                        _target=self.target,
                    )
