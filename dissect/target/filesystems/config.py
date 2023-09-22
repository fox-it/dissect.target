from __future__ import annotations

import io
from typing import Any, BinaryIO, Iterator, Optional, Union

from dissect.target import Target
from dissect.target.exceptions import ConfigurationParsingError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.helpers.configparser import (
    ConfigurationParser,
    ParserContents,
    parse_config,
)


def create_entry(
    fs, path: str, entry, hint: str, collapse: str, seperator: tuple[str], comment_prefixes: tuple[str]
) -> FilesystemEntry:
    if entry.is_file():
        contents = ParserContents(collapse, seperator, comment_prefixes)
        parser_items = parse_config(entry, hint, contents)
        return ConfigurationEntry(fs, path, entry, parser_items=parser_items)
    return entry


class ConfigurationFilesystem(VirtualFilesystem):
    __fstype__: str = "META:configuration"

    def __init__(self, target: Target, path: str = "/etc", **kwargs):
        super().__init__(**kwargs)
        self.root.top = target.fs.get(path)

    def _get_till_file(self, path, relentry) -> tuple[list[str], FilesystemEntry]:
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
        self,
        path: Optional[str] = None,
        relentry: Optional[FilesystemEntry] = None,
        hint: Optional[str] = None,
        collapse: Optional[Union[bool, set]] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> Union[FilesystemEntry, ConfigurationEntry]:
        parts, entry = self._get_till_file(path or "", relentry)

        for part in parts:
            if isinstance(entry, ConfigurationEntry):
                entry = entry.get(part)
            else:
                try:
                    entry = create_entry(self, part, entry, hint, collapse, seperator, comment_prefixes)
                except ConfigurationParsingError:
                    # All errors except parsing should be let through.
                    pass
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

    def get(self, path: Optional[str] = None) -> ConfigurationEntry:
        # Check for path in config entry
        if not path:
            # Return self if configuration was found.
            return self

        if path in self.parser_items:
            return ConfigurationEntry(self.fs, path, self.entry, self.parser_items[path])
        raise NotADirectoryError(f"Cannot open a {path!r} on a value")

    def _write_value_mapping(self, output: io.BytesIO, values: dict[str, Any]) -> None:
        """Writes a dictionary to the output, c style."""
        if isinstance(values, list):
            for value in values:
                output.write(bytes(value, "utf-8"))
                output.write(b"\n")
        elif hasattr(values, "keys"):
            output.write(b"\n")
            for key, value in values.items():
                output.write(bytes(key, "utf-8"))
                self._write_value_mapping(output, value)
        else:
            output.write(b" ")
            output.write(bytes(values))
            output.write(b"\n")

    def open(self) -> BinaryIO:
        # Return fh for path if entry is a file
        # Return bytes of value if entry is ConfigurationEntry

        if isinstance(self.parser_items, ConfigurationParser):
            # Currently trying to open the underlying entry
            return self.entry.open()

        if self.is_dir():
            bytesio = io.BytesIO()
            self._write_value_mapping(bytesio, self.parser_items)
            return bytesio
        return io.BytesIO(bytes(self.parser_items, "utf-8"))

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

    def __getitem__(self, item: str) -> ConfigurationEntry:
        return self.parser_items[item]
