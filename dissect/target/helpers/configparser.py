from __future__ import annotations

import io
import re
from configparser import ConfigParser, MissingSectionHeaderError
from dataclasses import dataclass
from typing import Any, ItemsView, KeysView, Optional, TextIO, Union

from dissect.target.exceptions import ConfigurationParsingError, FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import TargetPath


# TODO: Look if I can just create a parsing function and attach it to the
# the parser below.
class ConfigurationParser:
    def __init__(
        self,
        collapse: Optional[Union[bool, set]] = False,
        seperator: tuple[str] = ("=",),
        comment_prefixes: tuple[str] = (";", "#"),
    ) -> None:
        self.collapse_all = collapse is True
        self.collapse = collapse if isinstance(collapse, set) else set()
        self.seperator = seperator
        self.comment_prefixes = comment_prefixes
        self.parsed_data = {}

    def __getitem__(self, item: Any) -> Union[dict, str]:
        return self.parsed_data[item]

    def __contains__(self, item: str) -> bool:
        return item in self.parsed_data

    def parse_file(self, fh: TextIO) -> None:
        raise NotImplementedError()

    def get(self, item: str, default: Optional[Any] = None) -> Any:
        return self.parsed_data.get(item, default)

    def read_file(self, fh: TextIO) -> None:
        """Parse a configuration file.

        Raises:
            ConfigurationParsingError: If any exception occurs during during the parsing process
        """

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
    def __init__(
        self,
        collapse: Optional[Union[bool, set]] = True,
        seperator: tuple[str] = ("=",),
        comment_prefixes: tuple[str] = (";", "#"),
    ) -> None:
        super().__init__(
            collapse,
            seperator=seperator,
            comment_prefixes=comment_prefixes,
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
    """Read the file into ``content``, and show the bumber of bytes read."""

    def parse_file(self, fh: TextIO) -> None:
        # Cast the size to a string, to print it out later.
        self.parsed_data = {"content": fh.read(), "size": str(fh.tell())}


class Default(ConfigurationParser):
    """Parse a configuration file specified by ``seperator`` and ``comment_prefixes``.

    This parser splits only on the first ``seperator`` it finds:

        key<seperator>value    -> {"key": "value"}

        key<seperator>value\n  -> {"key": "value continuation"}
          continuation

        # Unless we collapse values, we add them to a list to not overwrite any values.
        key<seperator>value1   -> {key: [value1, value2]}
        key<seperator>value2

        <empty_space><comment> -> skip
    """

    def __init__(
        self,
        collapse: Optional[Union[bool, set]] = False,
        seperator: tuple[str] = (r"=",),
        comment_prefixes: tuple[str] = (";", "#"),
    ) -> None:
        super().__init__(collapse, seperator, comment_prefixes)
        self.SEPERATOR = re.compile(rf"\s*[{''.join(seperator)}]\s*")
        self.COMMENTS = re.compile(rf"\s*[{''.join(comment_prefixes)}]")

    def parse_file(self, fh: TextIO) -> None:
        information_dict = {}

        skip_lines = self.comment_prefixes + ("\n",)
        prev_key = (None, None)
        for line in fh.readlines():
            if line.strip().startswith(skip_lines) or not line.strip():
                continue

            # Strip the comments first
            line, *_ = self.COMMENTS.split(line, 1)

            if line.startswith((" ", "\t")):
                # This part was indented so it is a continuation of the previous key
                prev_value = information_dict.get(prev_key)
                information_dict[prev_key] = " ".join([prev_value, line.strip()])
                continue

            prev_key, *value = self.SEPERATOR.split(line, 1)
            value = value[0].strip() if value else ""

            if old_value := information_dict.get(prev_key):
                if not isinstance(old_value, list):
                    old_value = [old_value]
                value = old_value + [value]

            information_dict[prev_key] = value

        self.parsed_data = information_dict

    def _parse_line(self, line: str, data_dict: dict) -> tuple:
        key, *values = self.SEPERATOR.split(line)
        values = " ".join(value for value in values if value).strip()

        if old_value := data_dict.get(key):
            if not isinstance(old_value, list):
                old_value = [old_value]
            values = old_value + [values]
        data_dict[key] = values

        return key


@dataclass(frozen=True)
class ParserOptions:
    collapse: Optional[Union[bool, set]] = None
    seperator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None


@dataclass(frozen=True)
class ParserConfig:
    parser: type[ConfigurationParser] = Default
    collapse: Optional[Union[bool, set]] = None
    seperator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None

    def create_parser(self, options: Optional[ParserOptions] = None) -> ConfigurationParser:
        kwargs = {}

        for field_name in ["collapse", "seperator", "comment_prefixes"]:
            value = getattr(options, field_name, None) or getattr(self, field_name)
            if value:
                kwargs.update({field_name: value})

        return self.parser(**kwargs)


CONFIG_MAP: dict[str, ParserConfig] = {
    "ini": ParserConfig(Ini),
    "xml": ParserConfig(Txt),
    "json": ParserConfig(Txt),
    "cnf": ParserConfig(Default),
    "conf": ParserConfig(Default, seperator=(r"\s")),
    "sample": ParserConfig(Txt),
    "template": ParserConfig(Txt),
}
KNOWN_FILES: dict[str, type[ConfigurationParser]] = {
    "ulogd.conf": ParserConfig(Ini),
    "sshd_config": ParserConfig(Default, seperator=(r"\s",)),
    "hosts.allow": ParserConfig(Default, seperator=(":",), comment_prefixes=("#",)),
    "hosts.deny": ParserConfig(Default, seperator=(":",), comment_prefixes=("#",)),
    "hosts": ParserConfig(Default, seperator=(r"\s")),
}


def parse(
    path: Union[FilesystemEntry, TargetPath],
    hint: Optional[str] = None,
    collapse: Optional[Union[bool, set]] = None,
    seperator: Optional[tuple[str]] = None,
    comment_prefixes: Optional[tuple[str]] = None,
) -> ConfigParser:
    """Parses the content of an ``path`` or ``entry`` to a dictionary.

    Args:
        file_path: An entry or targetpath that with contents to parse
        hint: A hint to what parser should be used.
        collapse:
        seperator: What seperator to use for key value mapping
        comment_prefixes: The characters that determine a comment.

    Raises:
        FileNotFoundError: If the ``path`` is not a file.
    """

    if not path.is_file():
        raise FileNotFoundError(f"Could not parse {path} as a dictionary.")

    entry = path
    if isinstance(path, TargetPath):
        entry = path.get()

    options = ParserOptions(collapse, seperator, comment_prefixes)

    return parse_config(entry, hint, options)


def parse_config(
    entry: FilesystemEntry,
    hint: Optional[str] = None,
    options: Optional[ParserOptions] = None,
) -> ConfigParser:
    parser_type = _select_parser(entry, hint)

    parser = parser_type.create_parser(options)

    with entry.open() as fh:
        open_file = io.TextIOWrapper(fh, encoding="utf-8")
        parser.read_file(open_file)

    return parser


def _select_parser(entry: FilesystemEntry, hint: Optional[str] = None) -> ParserConfig:
    if hint and (parser_type := CONFIG_MAP.get(hint)):
        return parser_type

    extension = entry.path.rsplit(".", 1)[-1]

    extention_parser = CONFIG_MAP.get(extension, ParserConfig(Default))
    return KNOWN_FILES.get(entry.name, extention_parser)
