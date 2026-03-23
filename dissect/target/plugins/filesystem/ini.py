from __future__ import annotations

import io
from typing import TYPE_CHECKING

from dissect.target.exceptions import ConfigurationParsingError, FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath

IniRecord = TargetRecordDescriptor(
    "filesystem/iniFileRecord",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("string", "section"),
        ("string", "key"),
        ("string", "value"),
        ("path", "path"),
    ],
)


class IniPlugin(Plugin):
    """INI file plugin.

    This plugin scans target filesystems for INI configuration files and parses them into
    structured records. It handles both UTF-8 and UTF-16 encoded INI files
    """

    def check_compatible(self) -> None:
        if not len(self.target.fs.mounts):
            raise UnsupportedPluginError("No filesystems found on target")

    def on_error(self, error: Exception) -> None:
        """Error handler for filesystem traversal. Logs warnings for permission errors and other exceptions,
        but continues traversal.

        Args:
            error: ``Exception`` the exception thrown during filesystem traversal.
        """
        if isinstance(error, PermissionError):
            self.target.log.warning("Permission denied while scanning for ini files: %s", error)
            self.target.log.debug("", exc_info=error)
            return

        self.target.log.warning("Exception while scanning for ini files: %s", error)
        self.target.log.debug("", exc_info=error)

    def _iter_ini_files(self, path: str) -> Iterator[TargetPath]:
        """Find all INI files under the given path.

        Handles both explicit file paths and directory traversal. Continues traversal even if
        permission errors are encountered on individual directories.

        Args:
            path: ``string`` of Target filesystem path to scan. Can be a file or directory.

        Returns:
            Iterator yields ``TargetPath``
        """
        target_path = self.target.fs.path(path)
        if not target_path.exists():
            self.target.log.error("Provided path %s does not exist on target", target_path)
            return

        if target_path.is_file():
            if target_path.suffix.lower() == ".ini":
                yield target_path
            return

        for root, _dirs, files in self.target.fs.walk(path, onerror=self.on_error):
            root_path = self.target.fs.path(root)
            for file_name in files:
                if file_name.lower().endswith(".ini"):
                    yield root_path.joinpath(file_name)

    @export(record=IniRecord)
    @arg("-p", "--path", default="/", help="path to an .ini file or directory in target")
    def ini(self, path: str = "/") -> Iterator[IniRecord]:
        """Scan for and parse INI files, yielding structured records.

        This method recursively discovers INI configuration files under the specified path,
        parses them, and yields an IniRecord for each
        key-value pair found.

        Args:
            path: ``string`` of Target filesystem path to scan (default "/"). Can be a file or directory.

        Returns:
            Iterator yields ``IniRecord``: One record per key-value pair in discovered INI files.
        """
        for ini_file_path in self._iter_ini_files(path):
            try:
                config = _parse_ini(ini_file_path)
                stat = ini_file_path.stat()
            except FileNotFoundError as e:
                # File may disappear between compatibility check and parse.
                self.target.log.warning("File not found: %s", ini_file_path)
                self.target.log.debug("", exc_info=e)
                continue
            except Exception as e:
                self.target.log.warning("Exception generating ini record for %s: %s", ini_file_path, e)
                self.target.log.debug("", exc_info=e)
                continue

            for section_name, section in config.items():
                for key, value in section.items():
                    yield IniRecord(
                        atime=stat.st_atime,
                        mtime=stat.st_mtime,
                        ctime=stat.st_ctime,
                        section=section_name,
                        key=key,
                        value=str(value),
                        path=ini_file_path,
                        _target=self.target,
                    )


def _parse_ini(ini_file_path: TargetPath) -> configutil.ConfigurationParser:
    """Parse an INI file, with automatic fallback for UTF-16 encoded files.

    First attempts to parse the file with the default UTF-8 encoding. If a ConfigurationParsingError,
    retries using UTF-16 decoding

    Args:
        ini_file_path: ``TargetPath`` to the INI file to parse.

    Returns:
        ConfigurationParser: ``ConfigurationParser`` Parsed INI configuration object.
    """
    try:
        return configutil.parse(ini_file_path, hint="ini")
    except (UnicodeDecodeError, ConfigurationParsingError):
        # Many Windows INI files are UTF-16
        raw_data = ini_file_path.open("rb").read()
        text_data = raw_data.decode("utf-16")

        parser = configutil.Ini()
        parser.read_file(io.StringIO(text_data))
        return parser
