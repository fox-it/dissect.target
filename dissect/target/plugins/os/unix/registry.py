from __future__ import annotations

import io
from configparser import MissingSectionHeaderError, RawConfigParser
from typing import Any, Union

from dissect.target import Target
from dissect.target.exceptions import FilesystemError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.plugin import Plugin


class ConfigurationTree(Plugin):
    __namespace__ = "registry"

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._root = UnixRegistry(target)

    def check_compatible(self):
        if self.target.fs.get("/etc") is None:
            raise NotImplementedError()

    def key(self, key: str = None):
        if key:
            return self._root.get(key)
        return self._root.get("/")

    def keys(self, keys: Union[str, list[str]]):
        for key in keys:
            yield from self.key(key).iterdir()


class UnixRegistry(VirtualFilesystem):
    __fstype__: str = "META:registry"

    def __init__(self, target: Target, **kwargs):
        super().__init__(**kwargs)
        self.root.top = target.fs.get("/etc")

    def _get_till_file(self, path, relentry) -> tuple[list[str], FilesystemEntry]:
        entry = relentry or self.root
        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")

        if not path:
            return [], entry

        parts = path.split("/")

        for i, part in enumerate(parts):
            # If the entry of the previous part (or the starting relentry /
            # root entry) is a symlink, resolve it first so things like entry.up
            # work if it is a symlink to a directory.
            # Note that this will never resolve the final part of the path if
            # that happens to be a symlink, so things like fs.is_symlink() will
            # work.
            if entry.is_symlink():
                entry = entry.readlink_ext()

            if part == ".":
                continue
            elif part == "..":
                entry = entry.up or self.root
                continue

            try:
                entry = super().get(part, entry)
            except FilesystemError:
                break

        return parts[i:], entry

    def get(self, path: str, relentry=None) -> Union[FilesystemEntry, ConfigurationEntry]:
        parts, entry = self._get_till_file(path, relentry)

        for part in parts:
            if isinstance(entry, ConfigurationEntry):
                entry = entry.get(part)
            else:
                try:
                    entry = ConfigurationEntry(self, part, entry)
                except Exception:
                    pass

        return entry


class ConfigurationEntry(FilesystemEntry):
    def __init__(self, fs: Filesystem, path: str, entry: Any, parser_items=None) -> None:
        super().__init__(fs, path, entry)
        if parser_items is None:
            self.parser_items = self.parse_config(entry)
        else:
            self.parser_items = parser_items

    def parse_config(self, entry) -> RawConfigParser:
        parser = RawConfigParser(strict=False, delimiters=(" ", "\t"))
        parser.optionxform = str
        with entry.open() as fp:
            open_file = io.TextIOWrapper(fp, encoding="utf-8")
            try:
                parser.read_file(open_file, source=entry.name)
            except MissingSectionHeaderError:
                open_file.seek(0)
                open_file = io.StringIO("[DEFAULT]\n" + open_file.read())
                parser.read_file(open_file, source=entry.name)
        return parser

    def get(self, path: str) -> ConfigurationEntry:
        # Check for path in config entry
        if path in self.parser_items:
            return ConfigurationEntry(self.fs, path, self.entry, self.parser_items[path])
        raise NotADirectoryError(f"Cannot open a {path!r} on a value")

    def _write_value_mapping(self, output: io.BytesIO, data: dict[str, Any]):
        if hasattr(data, "keys"):
            output.write(b"\n")
            for key, value in data.items():
                output.write(bytes(key, "utf8"))
                self._write_value_mapping(output, value)
        else:
            output.write(b" ")
            output.write(bytes(data))
            output.write(b"\n")

    def open(self):
        # Return fh for path if entry is a file
        # Return bytes of value if entry is ConfigurationEntry

        if isinstance(self.parser_items, RawConfigParser):
            # Currently trying to open the underlying entry
            return self.entry.open()

        if self.is_dir():
            bytesio = io.BytesIO()
            for key, value in self.parser_items.items():
                bytesio.write(bytes(key, "utf8"))
                bytesio.write(b" ")
                bytesio.write(bytes(value))

        return io.BytesIO(bytes(self.parser_items, "utf8"))

    def iterdir(self):
        for entry in self.scandir():
            yield entry.name

    def scandir(self):
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
