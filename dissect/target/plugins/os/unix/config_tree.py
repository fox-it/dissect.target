from __future__ import annotations

import io
import re
from abc import abstractmethod
from configparser import ConfigParser, MissingSectionHeaderError
from typing import Any, ItemsView, KeysView, Optional, TextIO, Union

from dissect.target import Target
from dissect.target.exceptions import FilesystemError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.plugin import Plugin


# TODO: Look if I can just create a parsing function and attach it to the
# the parser below.
class LinuxConfigurationParser:
    def __init__(self, collapse: Optional[bool | set] = False) -> None:
        self.collapse_all = collapse is True
        self.collapse = collapse if isinstance(collapse, set) else {}
        self.parsed_data = {}

    @abstractmethod
    def parse_file(self, fh: TextIO) -> None:
        ...

    def __getitem__(self, item: Any) -> dict | str:
        return self.parsed_data[item]

    def __contains__(self, item: str):
        return item in self.parsed_data

    def read_file(self, fh: TextIO) -> None:
        self.parse_file(fh)

        if self.collapse_all or self.collapse:
            self.parsed_data = self._collapse_dict(self.parsed_data)

    def keys(self) -> KeysView:
        return self.parsed_data.keys()

    def items(self) -> ItemsView:
        return self.parsed_data.items()

    def _collapse_dict(self, dictionary: dict, collapse=False) -> dict:
        new_dictionary = {}

        if isinstance(dictionary, list) and collapse:
            return dictionary[-1]

        if not hasattr(dictionary, "items"):
            return dictionary

        for key, value in dictionary.items():
            value = self._collapse_dict(value, self.collapse_all or key in self.collapse)
            new_dictionary.update({key: value})

        return new_dictionary


class Ini(LinuxConfigurationParser):
    def __init__(self, collapse: Optional[bool | set] = True) -> None:
        super().__init__(collapse)

        self.parsed_data = ConfigParser(strict=False)
        self.parsed_data.optionxform = str

    def parse_file(self, fh: io.TextIO) -> None:
        self.parsed_data.read_file(fh)


class Unknown(LinuxConfigurationParser):
    EMPTY_SPACE = re.compile(r"\s+")

    def parse_file(self, fh: TextIO) -> None:
        new_info = {}
        for line in fh.readlines():
            if line.startswith(("#", "\n")):
                continue
            key, *values = self.EMPTY_SPACE.split(line)
            new_values = " ".join([value for value in values if value])

            if "#" in new_values:
                new_values = new_values.split("#")[0].strip()

            if old_value := new_info.get(key):
                if not isinstance(old_value, list):
                    old_value = [old_value]
                new_values = old_value + [new_values]
            new_info[key] = new_values

        self.parsed_data = new_info


CONFIG_MAP: dict[str, LinuxConfigurationParser] = {
    "ini": Ini,
}


def subkeys(self) -> list:
    subkeys = (key for key in self.scandir() if key.is_dir())
    yield from subkeys


def values(self) -> list:
    values = (key for key in self.scandir() if key.is_file())
    yield from values


class ConfigurationTree(Plugin):
    __namespace__ = "registry"

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self._root = ConfigurationFs(target)

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


class ConfigurationFs(VirtualFilesystem):
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

            try:
                entry = entry.get(part)
                if entry.is_file():
                    break
            except FilesystemError:
                break

        return parts[i:], entry

    def get(
        self,
        path: str,
        relentry=None,
        collapse: Optional[bool | set] = None,
    ) -> Union[FilesystemEntry, ConfigurationEntry]:
        parts, entry = self._get_till_file(path, relentry)

        for part in parts:
            if isinstance(entry, ConfigurationEntry):
                entry = entry.get(part)
            else:
                if entry.is_file():
                    try:
                        entry = ConfigurationEntry(self, part, entry, collapse=collapse)
                    except Exception:
                        pass
        return entry


class ConfigurationEntry(FilesystemEntry):
    def __init__(self, fs: Filesystem, path: str, entry: Any, parser_items=None, collapse=None) -> None:
        super().__init__(fs, path, entry)
        if parser_items is None:
            self.parser_items = self.parse_config(entry, collapse)
        else:
            self.parser_items = parser_items

    def parse_config(self, entry: FilesystemEntry, collapse=None) -> ConfigParser:
        extension = entry.path.rsplit(".", 1)[-1]
        parser = CONFIG_MAP.get(extension, Unknown)(collapse)
        with entry.open() as fp:
            open_file = io.TextIOWrapper(fp, encoding="utf-8")
            try:
                parser.read_file(open_file)
            except MissingSectionHeaderError:
                open_file.seek(0)
                open_file = io.StringIO("[DEFAULT]\n" + open_file.read())
                parser.read_file(open_file)
        return parser

    def get(self, path: str) -> ConfigurationEntry:
        # Check for path in config entry
        if path in self.parser_items:
            return ConfigurationEntry(self.fs, path, self.entry, self.parser_items[path])
        raise NotADirectoryError(f"Cannot open a {path!r} on a value")

    def _write_value_mapping(self, output: io.BytesIO, data: dict[str, Any]):
        if isinstance(data, list):
            for x in data:
                output.write(bytes(x, "utf-8"))
                output.write(b"\n")
        elif hasattr(data, "keys"):
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

        if isinstance(self.parser_items, LinuxConfigurationParser):
            # Currently trying to open the underlying entry
            return self.entry.open()

        if self.is_dir():
            bytesio = io.BytesIO()
            self._write_value_mapping(bytesio, self.parser_items)
            return bytesio
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

    def lstat(self) -> fsutil.stat_result:
        return self.entry.lstat()
