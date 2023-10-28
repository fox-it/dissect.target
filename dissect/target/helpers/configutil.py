from __future__ import annotations

import io
import re
from collections import deque
from configparser import ConfigParser, MissingSectionHeaderError
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, ItemsView, Iterator, KeysView, Optional, TextIO, Union

from dissect.target.exceptions import ConfigurationParsingError, FileNotFoundError
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.fsutil import TargetPath


def _update_dictionary(current: dict[str, Any], key: str, value: Any) -> None:
    if prev_value := current.get(key):
        if isinstance(prev_value, dict):
            # We can assume the value would be a dict too here.
            prev_value.update(value)
            return

        if isinstance(prev_value, str):
            prev_value = [prev_value]

        if isinstance(prev_value, list):
            # We want to append ``value`` to prev_value
            prev_value.append(value)

    current[key] = prev_value or value


class PeekableIterator:
    """Source gotten from:
    https://more-itertools.readthedocs.io/en/stable/_modules/more_itertools/more.html#peekable
    """

    def __init__(self, iterable):
        self._iterator = iter(iterable)
        self._cache = deque()

    def __iter__(self):
        return self

    def __next__(self):
        if self._cache:
            return self._cache.popleft()

        return next(self._iterator)

    def peek(self):
        if not self._cache:
            try:
                self._cache.append(next(self._iterator))
            except StopIteration:
                return
        return self._cache[0]


class ConfigurationParser:
    def __init__(
        self,
        collapse: Union[bool, set] = False,
        collapse_inverse: bool = False,
        seperator: tuple[str] = ("=",),
        comment_prefixes: tuple[str] = (";", "#"),
    ) -> None:
        self.collapse_all = collapse is True
        self.collapse = collapse if isinstance(collapse, set) else set()
        self._collapse_check = self._key_not_in_collapse if collapse_inverse else self._key_in_collapse

        self.seperator = seperator
        self.comment_prefixes = comment_prefixes
        self.parsed_data = {}

    def __getitem__(self, item: Any) -> Union[dict, str]:
        return self.parsed_data[item]

    def __contains__(self, item: str) -> bool:
        return item in self.parsed_data

    def _collapse_dict(self, dictionary: dict, collapse: bool = False) -> dict[str, dict]:
        new_dictionary = {}

        if isinstance(dictionary, list) and collapse:
            return dictionary[-1]

        if not hasattr(dictionary, "items"):
            return dictionary

        for key, value in dictionary.items():
            value = self._collapse_dict(value, self.collapse_all or self._collapse_check(key))
            new_dictionary.update({key: value})

        return new_dictionary

    def _key_in_collapse(self, key: str) -> bool:
        return key in self.collapse

    def _key_not_in_collapse(self, key: str) -> bool:
        return key not in self.collapse

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


class Default(ConfigurationParser):
    """Parse a configuration file specified by ``seperator`` and ``comment_prefixes``.

    This parser splits only on the first ``seperator`` it finds:

        key<seperator>value     -> {"key": "value"}

        key<seperator>value\n
          continuation
                                -> {"key": "value continuation"}

        # Unless we collapse values, we add them to a list to not overwrite any values.
        key<seperator>value1
        key<seperator>value2
                                -> {key: [value1, value2]}

        <empty_space><comment>  -> skip
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.SEPERATOR = re.compile(rf"\s*[{''.join(self.seperator)}]\s*")
        self.COMMENTS = re.compile(rf"\s*[{''.join(self.comment_prefixes)}]")
        self.skip_lines = self.comment_prefixes + ("\n",)

    def line_reader(self, fh: TextIO) -> Iterator[str]:
        for line in fh:
            if line.strip().startswith(self.skip_lines) or not line.strip():
                continue

            # Strip the comments first
            line, *_ = self.COMMENTS.split(line, 1)
            yield line

    def parse_file(self, fh: TextIO) -> None:
        information_dict = {}

        prev_key = None
        for line in self.line_reader(fh):
            if line.startswith((" ", "\t")):
                # This part was indented so it is a continuation of the previous key
                prev_value = information_dict.get(prev_key)
                information_dict[prev_key] = " ".join([prev_value, line.strip()])
                continue

            prev_key, *value = self.SEPERATOR.split(line, 1)
            value = value[0].strip() if value else ""

            _update_dictionary(information_dict, prev_key, value)

        self.parsed_data = information_dict


class Ini(ConfigurationParser):
    """Parses an ini file according using the built-in python ConfigParser"""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.parsed_data = ConfigParser(
            strict=False,
            delimiters=self.seperator,
            comment_prefixes=self.comment_prefixes,
            allow_no_value=True,
            interpolation=None,
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


class Indentation(Default):
    """This parser is used for the files that use a single level of indentation to specify a different scope.

    Examples of these files are for example the sshd_config file.
    Where "Match" statments use a single layer of indentaiton to specify a scope for the key value pairs.

    The parser parses this as the following:

      key value
        key2 value2
                       -> {"key value": {"key2": "value2"}}
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._parents = {}
        self._indentation = 0

    def _parse_line(self, line: str) -> tuple[str, str]:
        key, *value = self.SEPERATOR.split(line.strip(), 1)
        value = value[0].strip() if value else ""
        return key, value

    def _push_scope(self, name: str, current: dict[str, Union[str, dict]]) -> dict[str, Union[str, dict]]:
        child = current.get(name, {})

        parent = current
        self._parents[id(child)] = parent
        parent[name] = child
        return child

    def _pop_scope(self, current: dict[str, Union[str, dict]]) -> dict[str, Union[str, dict]]:
        self._indentation = 0
        return self._parents.pop(id(current), current)

    def _change_scope(
        self,
        line: str,
        next_line: Optional[str],
        key: Optional[str],
        current: dict[str, Union[str, dict]],
    ) -> dict[str, Union[str, dict]]:
        empty_space = (" ", "\t")

        if next_line is None:
            return current

        if not line.startswith(empty_space):
            current = self._pop_scope(current)

        if not line.startswith(empty_space) and next_line.startswith(empty_space):
            self._indentation = len(next_line) - len(next_line.lstrip())
            return self._push_scope(key, current)
        return current

    def parse_file(self, fh: TextIO) -> None:
        root = {}
        current = root

        iterator = PeekableIterator(self.line_reader(fh))
        prev_key = None
        for line in iterator:
            key, value = self._parse_line(line)
            prev_dict = current
            current = self._change_scope(line, iterator.peek(), line.strip(), current)

            if id(current) != id(prev_dict):
                prev_key = line.strip()
                continue

            if not value:
                key, value = prev_key, key
                current = self._pop_scope(current)

            _update_dictionary(current, key, value)

        self.parsed_data = root
        # Cleanup of internal state
        self._parents = {}
        self._indentation = 0


@dataclass(frozen=True)
class ParserOptions:
    collapse: Optional[Union[bool, set]] = None
    collapse_inverse: Optional[bool] = None
    seperator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None


@dataclass(frozen=True)
class ParserConfig:
    parser: type[ConfigurationParser] = Default
    collapse: Optional[Union[bool, set]] = None
    collapse_inverse: Optional[bool] = None
    seperator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None

    def create_parser(self, options: Optional[ParserOptions] = None) -> ConfigurationParser:
        kwargs = {}

        for field_name in ["collapse", "collapse_inverse", "seperator", "comment_prefixes"]:
            value = getattr(options, field_name, None) or getattr(self, field_name)
            if value:
                kwargs.update({field_name: value})

        return self.parser(**kwargs)


MATCH_MAP: dict[str, ParserConfig] = {
    "*/systemd/*": ParserConfig(Ini),
    "*/sysconfig/network-scripts/ifcfg-*": ParserConfig(Default),
    "*/sysctl.d/*.conf": ParserConfig(Default),
}


CONFIG_MAP: dict[tuple[str, ...], ParserConfig] = {
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
    "sshd_config": ParserConfig(Indentation, seperator=(r"\s",)),
    "hosts.allow": ParserConfig(Default, seperator=(":",), comment_prefixes=("#",)),
    "hosts.deny": ParserConfig(Default, seperator=(":",), comment_prefixes=("#",)),
    "hosts": ParserConfig(Default, seperator=(r"\s")),
    "nsswitch.conf": ParserConfig(Default, seperator=(":",)),
    "lsb-release": ParserConfig(Default),
}


def parse(path: Union[FilesystemEntry, TargetPath], hint: Optional[str] = None, *args, **kwargs) -> ConfigParser:
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

    options = ParserOptions(*args, **kwargs)

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

    for match, value in MATCH_MAP.items():
        if fnmatch(entry.path, f"{match}"):
            return value

    extension = entry.path.rsplit(".", 1)[-1]

    extention_parser = CONFIG_MAP.get(extension, ParserConfig(Default))
    return KNOWN_FILES.get(entry.name, extention_parser)
