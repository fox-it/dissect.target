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
    "filesystem/ini",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("string", "section"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
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

    def _iter_ini_files(self, path: str) -> Iterator:
        """Find all INI files under the given path.

        Handles both explicit file paths and directory traversal. Continues traversal even if
        permission errors are encountered on individual directories.

        Args:
            path: Target filesystem path to scan. Can be a file or directory.

        Returns:
            TargetPath objects for each discovered .ini file.
        """
        target_path = self.target.fs.path(path)
        if not target_path.exists():
            self.target.log.error("Provided path %s does not exist on target", target_path)
            return

        if target_path.is_file():
            if target_path.suffix.lower() == ".ini":
                yield target_path
            return

        def on_error(error: Exception) -> None:
            if isinstance(error, PermissionError):
                self.target.log.warning("Permission denied while scanning for ini files: %s", error)
                self.target.log.debug("", exc_info=error)
                return

            self.target.log.warning("Exception while scanning for ini files: %s", error)
            self.target.log.debug("", exc_info=error)

        for root, _dirs, files in self.target.fs.walk(path, onerror=on_error):
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
            path: Target filesystem path to scan (default "/"). Can be a file or directory.

        Returns:
            IniRecord: One record per key-value pair in discovered INI files.
        """
        for source in self._iter_ini_files(path):
            try:
                config = _parse_ini(source)
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

            for section_name, section in config.items():
                for key, value in section.items():
                    yield IniRecord(
                        atime=stat.st_atime,
                        mtime=stat.st_mtime,
                        ctime=stat.st_ctime,
                        section=section_name,
                        key=key,
                        value="" if value is None else str(value),
                        source=source,
                        _target=self.target,
                    )


def _parse_ini(source: TargetPath) -> configutil.ConfigurationParser:
    """Parse an INI file, with automatic fallback for UTF-16 encoded files.

    First attempts to parse the file with the default UTF-8 encoding. If a UnicodeDecodeError
    occurs (often wrapped in ConfigurationParsingError), retries using UTF-16 decoding, which
    handles Windows INI files with BOM markers.

    Args:
        source: TargetPath to the INI file to parse.

    Returns:
        ConfigurationParser: Parsed INI configuration object.
    """
    try:
        return configutil.parse(source, hint="ini")
    except (UnicodeDecodeError, ConfigurationParsingError) as e:
        # ConfigurationParsingError may wrap a UnicodeDecodeError
        if isinstance(e, ConfigurationParsingError) and not isinstance(e.__cause__, UnicodeDecodeError):
            raise

        # Many Windows INI files are UTF-16 with BOM; parse those explicitly.
        raw_data = source.open("rb").read()
        text_data = raw_data.decode("utf-16")

        parser = configutil.Ini()
        parser.read_file(io.StringIO(text_data))
        return parser
