from __future__ import annotations

import io
import re
from abc import abstractmethod
from configparser import ConfigParser, MissingSectionHeaderError
from typing import Any, BinaryIO, ItemsView, Iterator, KeysView, Optional, TextIO, Union

from dissect.target import Target
from dissect.target.exceptions import ConfigurationParsingError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil


# TODO: Look if I can just create a parsing function and attach it to the
# the parser below.
class ConfigurationParser:
    def __init__(
        self,
        collapse: Optional[Union[bool, set]] = False,
        seperator: tuple = ("=",),
        comment_prefixes: tuple = (";", "#"),
    ) -> None:
        self.collapse_all = collapse is True
        self.collapse = collapse if isinstance(collapse, set) else {}
        self.seperator = seperator
        self.comment_prefixes = comment_prefixes
        self.parsed_data = {}

    @abstractmethod
    def parse_file(self, fh: TextIO) -> None:
        ...

    def __getitem__(self, item: Any) -> Union[dict, str]:
        return self.parsed_data[item]

    def __contains__(self, item: str) -> bool:
        return item in self.parsed_data

    def get(self, item: str, default: Optional[Any] = None) -> Any:
        try:
            return self.parsed_data[item]
        except KeyError:
            return default

    def read_file(self, fh: TextIO) -> None:
        try:
            self.parse_file(fh)
        except Exception as e:
            raise ConfigurationParsingError from e

        if self.collapse_all or self.collapse:
            self.parsed_data = self._collapse_dict(self.parsed_data)

    def keys(self) -> KeysView:
        return self.parsed_data.keys()

    def items(self) -> ItemsView:
        return self.parsed_data.items()

    def _collapse_dict(self, dictionary: dict, collapse: bool = False) -> dict[str, dict]:
        new_dictionary = {}

        if isinstance(dictionary, list) and collapse:
            return dictionary[-1]

        if not hasattr(dictionary, "items"):
            return dictionary

        for key, value in dictionary.items():
            value = self._collapse_dict(value, self.collapse_all or key in self.collapse)
            new_dictionary.update({key: value})

        return new_dictionary


class Ini(ConfigurationParser):
    def __init__(self, collapse: Optional[Union[bool, set]] = True) -> None:
        super().__init__(
            collapse,
            seperator=("=", ";"),
            comment_prefixes=(";", "#"),
        )

        self.parsed_data = ConfigParser(
            strict=False,
            delimiters=self.seperator,
            comment_prefixes=self.comment_prefixes,
        )
        self.parsed_data.optionxform = str

    def parse_file(self, fh: io.TextIO) -> None:
        offset = fh.tell()
        try:
            self.parsed_data.read_file(fh)
            return
        except MissingSectionHeaderError:
            pass

        fh.seek(offset)
        open_file = io.StringIO("[DEFAULT]\n" + fh.read())
        self.parsed_data.read_file(open_file)


class Txt(ConfigurationParser):
    def parse_file(self, fh: TextIO) -> None:
        self.parsed_data = {"content": fh.read(), "size": str(fh.tell())}


class Default(ConfigurationParser):
    def __init__(
        self,
        collapse: Optional[Union[bool, set]] = False,
        seperator: str = (r"\s",),
        comment_prefixes: tuple = (";", "#"),
    ) -> None:
        super().__init__(collapse, seperator, comment_prefixes)
        self.SEPERATOR = re.compile(rf"\s*?[{''.join(seperator)}]\s*?")
        self.COMMENTS = re.compile(rf"\s*[{''.join(comment_prefixes)}]")

    def parse_file(self, fh: TextIO) -> None:
        information_dict = {}

        skip_lines = self.comment_prefixes + ("\n",)
        prev_key = None, None
        for line in fh.readlines():
            if line.startswith(skip_lines):
                continue

            # Strip the comments first
            line, *_ = self.COMMENTS.split(line)

            if not line:
                # There was an indented comment
                continue

            if line.startswith((" ", "\t")) and line.strip():
                # This part was indented
                # So this one belongs to the previous key
                new_dictionary = dict()
                self.parse_value(line.strip(), new_dictionary)
                information_dict[prev_key] = {information_dict.get(prev_key): new_dictionary}
                continue

            key = self.parse_value(line, information_dict)
            prev_key = key

        self.parsed_data = information_dict

    def parse_value(self, line: str, data_dict: dict) -> tuple:
        key, *values = self.SEPERATOR.split(line)
        values = " ".join(value for value in values if value).strip()

        if old_value := data_dict.get(key):
            if not isinstance(old_value, list):
                old_value = [old_value]
            values = old_value + [values]
        data_dict[key] = values

        return key


CONFIG_MAP: dict[str, type[ConfigurationParser]] = {
    "ini": (Ini,),
    "xml": (Txt,),
    "json": (Txt,),
    "cnf": (Default,),
    "conf": (Default, (r"\s",)),
    "sample": (Txt,),
    "template": (Txt,),
}
KNOWN_FILES: dict[str, type[ConfigurationParser]] = {
    "ulogd.conf": (Ini,),
    "hosts.allow": (Default, (":",), ("#",)),
    "hosts.deny": (Default, (":",), ("#",)),
    "hosts": (Default, (r"\s")),
}


class ConfigurationFilesystem(VirtualFilesystem):
    __fstype__: str = "META:configurations"

    def __init__(self, target: Target, **kwargs):
        super().__init__(**kwargs)
        self.root.top = target.fs.get("/etc")

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
        path: str,
        relentry: Optional[FilesystemEntry] = None,
        collapse: Optional[Union[bool, set]] = None,
    ) -> Union[FilesystemEntry, ConfigurationEntry]:
        parts, entry = self._get_till_file(path, relentry)

        for part in parts:
            if isinstance(entry, ConfigurationEntry):
                entry = entry.get(part)
            elif entry.is_file():
                try:
                    entry = ConfigurationEntry(self, part, entry, collapse=collapse)
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
        collapse: Optional[Union[bool, set]] = None,
    ) -> None:
        super().__init__(fs, path, entry)
        if parser_items is None:
            self.parser_items = self.parse_config(entry, collapse)
        else:
            self.parser_items = parser_items

    def parse_config(self, entry: FilesystemEntry, collapse: Optional[Union[bool, set]] = None) -> ConfigParser:
        extension = entry.path.rsplit(".", 1)[-1]

        known_extention = CONFIG_MAP.get(extension, (Default,))
        parser_type, *additional_data = KNOWN_FILES.get(entry.name, known_extention)

        parser = parser_type(collapse, *additional_data)

        with entry.open() as fh:
            open_file = io.TextIOWrapper(fh, encoding="utf-8")
            parser.read_file(open_file)

        return parser

    def get(self, path: str) -> ConfigurationEntry:
        # Check for path in config entry
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
