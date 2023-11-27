from __future__ import annotations

import io
import textwrap
from logging import getLogger
from typing import Any, BinaryIO, Iterator, Optional, Union

from dissect.target import Target
from dissect.target.exceptions import ConfigurationParsingError, FileNotFoundError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.helpers.configutil import ConfigurationParser, parse

log = getLogger(__name__)


class ConfigurationFilesystem(VirtualFilesystem):
    __type__: str = "META:configuration"

    def __init__(self, target: Target, path: str, **kwargs):
        super().__init__(**kwargs)
        self.root.top = target.fs.get(path)

    def _get_till_file(self, path: str, relentry: FilesystemEntry) -> tuple[list[str], FilesystemEntry]:
        """Searches for the file entry that is pointed to by ``path``.

        The ``path`` could contain ``key`` entries too, so it searches for the entry from
        the start of the path.

        Returns:
            A list of ``parts``: [filename, keys, into, the, file].
            And the resolved entry.
        """
        entry = relentry or self.root

        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")

        if not path:
            return [], entry

        parts = path.split("/")

        for idx, part in enumerate(parts):
            # Resolve link
            if entry.is_symlink():
                entry = entry.readlink_ext()

            if part == ".":
                continue
            elif part == "..":
                entry = entry.up or self.root
                continue

            if entry is self.root:
                entry = self.root.top

            entry = entry.get(part)
            if entry.is_file():
                break

        return parts[idx:], entry

    def get(
        self, path: str, relentry: Optional[FilesystemEntry] = None, *args, **kwargs
    ) -> Union[FilesystemEntry, ConfigurationEntry]:
        parts, entry = self._get_till_file(path, relentry)

        for part in parts:
            if isinstance(entry, ConfigurationEntry):
                entry = entry.get(part)
            else:
                try:
                    # The parts in _get_till_file also includes the filename, so we do not join
                    # the part with entry.path here.
                    config_parser = parse(entry, *args, **kwargs)
                    entry = ConfigurationEntry(self, entry.path, entry, config_parser)
                except (FileNotFoundError, ConfigurationParsingError):
                    # If a parsing error gets created, it should return the `entry`
                    log.debug(f"Error when parsing {entry.path}/{part}")
        return entry


class ConfigurationEntry(FilesystemEntry):
    def __init__(
        self,
        fs: Filesystem,
        path: str,
        entry: FilesystemEntry,
        parser_items: Optional[Union[dict, Any]] = None,
    ) -> None:
        super().__init__(fs, path, entry)
        self.parser_items = parser_items

    def __getitem__(self, item: str) -> ConfigurationEntry:
        return self.parser_items[item]

    def get(self, path: Optional[str] = None) -> ConfigurationEntry:
        # Check for path in config entry
        if not path:
            # Return self if configuration was found.
            return self

        if path in self.parser_items:
            return ConfigurationEntry(
                self.fs,
                fsutil.join(self.path, path, alt_separator=self.fs.alt_separator),
                self.entry,
                self.parser_items[path],
            )
        raise NotADirectoryError(f"Cannot open a {path!r} on a value")

    def _write_value_mapping(self, values: dict[str, Any], indentation_nr=0) -> str:
        """Writes a dictionary to the output, c style."""
        prefix = " " * indentation_nr
        output_buffer = io.StringIO()

        if isinstance(values, list):
            output_buffer.write(textwrap.indent(text="\n".join(values), prefix=prefix))
        elif hasattr(values, "keys"):
            for key, value in values.items():
                output_buffer.write(textwrap.indent(key, prefix=prefix) + "\n")
                output_buffer.write(self._write_value_mapping(value, indentation_nr + 4))
        else:
            output_buffer.write(textwrap.indent(values, prefix=prefix) + "\n")

        return output_buffer.getvalue()

    def open(self) -> BinaryIO:
        # Return fh for path if entry is a file
        # Return bytes of value if entry is ConfigurationEntry

        if isinstance(self.parser_items, ConfigurationParser):
            # Currently trying to open the underlying entry
            return self.entry.open()

        output_data = self._write_value_mapping(self.parser_items)
        return io.BytesIO(bytes(output_data, "utf-8"))

    def iterdir(self) -> Iterator[str]:
        for entry in self.scandir():
            yield entry.name

    def scandir(self) -> Iterator[ConfigurationEntry]:
        # Return dict keys
        if self.is_file():
            raise NotADirectoryError()

        for key, values in self.parser_items.items():
            yield ConfigurationEntry(self.fs, key, self.entry, values)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return not self.is_dir(follow_symlinks)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return hasattr(self.parser_items, "keys")

    def is_symlink(self) -> bool:
        return False

    def exists(self, path: str) -> bool:
        return self.entry.exists() and path in self.parser_items

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.entry.stat(follow_symlinks)

    def lstat(self) -> fsutil.stat_result:
        return self.entry.lstat()

    def as_dict(self) -> dict:
        return self.parser_items
