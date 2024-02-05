from __future__ import annotations

import io
import re
from collections import deque
from configparser import ConfigParser, MissingSectionHeaderError
from dataclasses import dataclass
from fnmatch import fnmatch
from types import TracebackType
from typing import (
    Any,
    Callable,
    ItemsView,
    Iterable,
    Iterator,
    KeysView,
    Literal,
    Optional,
    TextIO,
    Union,
)

from defusedxml import ElementTree

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
    """A configuration parser where you can configure certain aspects of the parsing mechanism.

    Attributes:
        parsed_data: The resulting dictionary after parsing.

    Args:
        collapse: A ``bool`` or an ``Iterator``:
          If ``True``: it will collapse all the resulting dictionary values.
          If an ``Iterable`` it will collapse on the keys defined in ``collapse``.
        collapse_inverse: Inverses the collapsing mechanism. Collapse on everything that is not inside ``collapse``.
        separator: Contains what values it should look for as a separator.
        comment_prefixes: Contains what constitutes as a comment.
    """

    def __init__(
        self,
        collapse: Union[bool, Iterable[str]] = False,
        collapse_inverse: bool = False,
        separator: tuple[str] = ("=",),
        comment_prefixes: tuple[str] = (";", "#"),
    ) -> None:
        self.collapse_all = collapse is True
        self.collapse = set(collapse) if isinstance(collapse, Iterable) else set()
        self._collapse_check = self._key_not_in_collapse if collapse_inverse else self._key_in_collapse

        self.separator = separator
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
        """Parse the contents of ``fh`` into key/value pairs.

        This function should **set** :attr:`parsed_data` as a side_effect.

        Args:
            fh: The text to parse.
        """
        raise NotImplementedError()

    def get(self, item: str, default: Optional[Any] = None) -> Any:
        return self.parsed_data.get(item, default)

    def read_file(self, fh: TextIO) -> None:
        """Parse a configuration file.

        Raises:
            ConfigurationParsingError: If any exception occurs during during the parsing process.
        """

        try:
            self.parse_file(fh)
        except Exception as e:
            raise ConfigurationParsingError from e

        if self.collapse_all or self.collapse:
            self.parsed_data = self._collapse_dict(self.parsed_data)

        if not isinstance(self.parsed_data, dict):
            self.parsed_data = self._collapse_dict(self.parsed_data, False)

    def keys(self) -> KeysView:
        return self.parsed_data.keys()

    def items(self) -> ItemsView:
        return self.parsed_data.items()


class Default(ConfigurationParser):
    """Parse a configuration file specified by ``separator`` and ``comment_prefixes``.

    This parser splits only on the first ``separator`` it finds:

        key<separator>value     -> {"key": "value"}

        key<separator>value\n
          continuation
                                -> {"key": "value continuation"}

        # Unless we collapse values, we add them to a list to not overwrite any values.
        key<separator>value1
        key<separator>value2
                                -> {key: [value1, value2]}

        <empty_space><comment>  -> skip
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.SEPARATOR = re.compile(rf"\s*[{''.join(self.separator)}]\s*")
        self.COMMENTS = re.compile(rf"\s*[{''.join(self.comment_prefixes)}]")
        self.skip_lines = self.comment_prefixes + ("\n",)

    def line_reader(self, fh: TextIO, strip_comments: bool = True) -> Iterator[str]:
        for line in fh:
            if line.strip().startswith(self.skip_lines) or not line.strip():
                continue

            if strip_comments:
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

            prev_key, *value = self.SEPARATOR.split(line, 1)
            value = value[0].strip() if value else ""

            _update_dictionary(information_dict, prev_key, value)

        self.parsed_data = information_dict


class Ini(ConfigurationParser):
    """Parses an ini file according using the built-in python ConfigParser"""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.parsed_data = ConfigParser(
            strict=False,
            delimiters=self.separator,
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


class Xml(ConfigurationParser):
    """Parses an XML file. Ignores any constructor parameters passed from ``ConfigurationParser`."""

    def _tree(self, tree: ElementTree, root: bool = False) -> dict:
        """Very simple but robust xml -> dict implementation, see comments."""
        nodes = {}
        result = {}
        counter = {}

        # each node is a folder (so the structure is always the same! [1])
        for node in tree.findall("*"):
            # if a node contains multiple nodes with the same name, number them
            if node.tag in counter:
                counter[node.tag] += 1
                nodes[f"{node.tag}-{counter[node.tag]}"] = self._tree(node)
            else:
                counter[node.tag] = 1
                nodes[node.tag] = self._tree(node)

        # all attribs go in the attribute folder
        # (i.e. stable, does not change depending on xml structure! [2]
        # Also, this way we "know" they have been attributes, i.e. we don't lose information! [3]
        if tree.attrib:
            result["attributes"] = tree.attrib

        # all subnodes go in the nodes folder
        if nodes:
            result["nodes"] = nodes

        # content goes into the text folder
        # we don't use special prefixes ($) because XML docs may use them anyway (even though they are forbidden)
        if tree.text:
            if text := tree.text.strip(" \n\r"):
                result["text"] = text

        # if you need to store meta-data, you can extend add more entries here... CDATA, Comments, errors
        result = {tree.tag: result} if root else result
        return result

    def _fix(self, content: str, position: tuple(int, int)) -> str:
        """Quick heuristic fix. If there is an invalid token, just remove it."""
        lineno, offset = position
        lines = content.split("\n")

        line = lines[lineno - 1]
        line = line[: offset - 1] + "" + line[offset + 1 :]

        lines[lineno - 1] = line

        return "\n".join(lines)

    def parse_file(self, fh: TextIO) -> None:
        content = fh.read()
        document = content
        errors = 0
        limit = 20
        tree = {}

        while not tree and errors < limit:
            try:
                tree = self._tree(ElementTree.fromstring(document), root=True)
                break
            except ElementTree.ParseError as err:
                errors += 1
                document = self._fix(document, err.position)

        if not tree:
            # Error limit reached. Thus we consider the document not parseable.
            raise ConfigurationParsingError(f"Could not parse XML file: {fh.name} after {errors} attempts.")

        self.parsed_data = tree


class ScopeManager:
    """A (context)manager for dictionary scoping.

    This class provides utility functions to keep track of scopes inside a dictionary.

    Attributes:
        _parents: A dictionary accounting what child belongs to which parent dictionary.
        _root: The initial dictionary.
        _current: The current dictionary.
        _previous: The node before the current (changed) node.
    """

    def __init__(self) -> None:
        self._parents = {}
        self._root = {}
        self._current = self._root
        self._previous = None

    def __enter__(self) -> ScopeManager:
        return self

    def __exit__(
        self,
        type: Optional[type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.clean()

    def _set_prev(self, keep_prev: bool) -> None:
        """Set :attr:`_previous` before :attr:`_current` changes."""
        if not keep_prev:
            self._previous = self._current

    def push(self, name: str, keep_prev: bool = False) -> Literal[True]:
        """Push a new key to the :attr:`_current` dictionary and return that we did."""
        child = self._current.get(name, {})

        parent = self._current
        self._parents[id(child)] = parent
        parent[name] = child
        self._set_prev(keep_prev)
        self._current = child
        return True

    def pop(self, keep_prev: bool = False) -> bool:
        """Pop :attr:`_current` and return whether we changed the :attr:`_parents` dictionary."""
        if new_current := self._parents.pop(id(self._current), None):
            self._set_prev(keep_prev)
            self._current = new_current
            return True
        return False

    def update(self, key: str, value: str) -> None:
        """Update the :attr:`_current` dictionary with ``key`` and ``value``."""
        _update_dictionary(self._current, key, value)

    def update_prev(self, key: str, value: str) -> None:
        """Update the :attr:`_previous` dictionary with ``key`` and ``value``."""
        _update_dictionary(self._previous, key, value)

    def is_root(self) -> bool:
        """Utility function to check whether the current dictionary is a root dictionary."""
        return id(self._current) == id(self._root)

    def clean(self) -> None:
        """Clean up the internal state.
        This is called automatically when :class:`ScopeManager` is used as a contextmanager.
        """
        self._parents = {}
        self._root = {}
        self._current = self._root
        self._previous = None


class Indentation(Default):
    """This parser is used for files that use a single level of indentation to specify a different scope.

    Examples of these files are the ``sshd_config`` file.
    Where "Match" statements use a single layer of indentation to specify a scope for the key value pairs.

    The parser parses this as the following:

      key value
        key2 value2
                       -> {"key value": {"key2": "value2"}}
    """

    def _parse_line(self, line: str) -> tuple[str, str]:
        key, *value = self.SEPARATOR.split(line.strip(), 1)
        value = value[0].strip() if value else ""
        return key, value

    def _change_scope(
        self,
        manager: ScopeManager,
        line: str,
        key: str,
        next_line: Optional[str] = None,
    ) -> bool:
        """A function to check whether to create a new scope, or go back to a previous one.

        Args:
            manager: A :class:`ScopeManager` that contains the logic to ``push`` and ``pop`` scopes. And keeps state.
            line: The line to be parsed.
            key: The key that should be updated during a :method:`ScopeManager.push``.
            next_line: The next line to be parsed.

        Returns:
            Whether the scope changed or not.
        """
        empty_space = (" ", "\t")
        changed = False

        if next_line is None:
            return False

        if not line.startswith(empty_space):
            changed = manager.pop()

        if not line.startswith(empty_space) and next_line.startswith(empty_space):
            return manager.push(key)
        return changed

    def parse_file(self, fh: TextIO) -> None:
        iterator = PeekableIterator(self.line_reader(fh))
        prev_key = None

        with ScopeManager() as manager:
            for line in iterator:
                key, value = self._parse_line(line)
                changed = self._change_scope(
                    manager=manager,
                    line=line,
                    key=line.strip(),
                    next_line=iterator.peek(),
                )

                if changed:
                    prev_key = line.strip()
                    continue

                if not value:
                    key, value = prev_key, key
                    manager.pop()

                manager.update(key, value)

            self.parsed_data = manager._root


class SystemD(Indentation):
    """A :class:`ConfigurationParser` that specifically parses systemd configuration files.

    Examples:
        >>> systemd_data = textwrap.dedent(
                '''
                [Section1]
                Key=Value
                [Section2]
                Key2=Value 2\\
                    Value 2 continued
                '''
            )
        >>> parser = SystemD(io.StringIO(systemd_data))
        >>> parser.parser_items
        {
            "Section1": {
                "Key": "Value
            },
            "Section2": {
                "Key2": "Value2 Value 2 continued
            }
        }

    """

    def _change_scope(
        self,
        manager: ScopeManager,
        line: str,
        key: str,
        next_line: Optional[str] = None,
    ) -> bool:
        scope_char = ("[", "]")
        changed = False
        if line.startswith(scope_char):
            if not manager.is_root():
                changed = manager.pop()
            stripped_characters = "".join(scope_char)
            changed = manager.push(key.strip(stripped_characters), changed)

        return changed

    def parse_file(self, fh: TextIO) -> None:
        prev_values = []
        prev_key = None

        with ScopeManager() as manager:
            for line in self.line_reader(fh, strip_comments=False):
                changed = self._change_scope(
                    manager=manager,
                    line=line,
                    key=line.strip(),
                )

                if changed:
                    # Current part is a section header.
                    if prev_values:
                        # Update previous key/value... someone configured it wrong
                        prev_values, prev_key = self._update_continued_values(
                            func=manager.update_prev,
                            key=prev_key,
                            values=prev_values,
                        )
                    continue

                key, value = self._parse_line(line)

                continued_value = value or key
                if continued_value.endswith("\\"):
                    prev_key = prev_key or key
                    prev_values.append(continued_value.strip("\\ "))
                    continue

                if prev_values:
                    prev_values, prev_key = self._update_continued_values(
                        func=manager.update,
                        key=prev_key,
                        values=prev_values + [continued_value],
                    )
                    continue

                manager.update(key, value)

            self.parsed_data = manager._root

    def _update_continued_values(self, func: Callable, key, values: list[str]) -> tuple[list, None]:
        value = " ".join(values)
        func(key, value)
        return [], None


@dataclass(frozen=True)
class ParserOptions:
    collapse: Optional[Union[bool, set]] = None
    collapse_inverse: Optional[bool] = None
    separator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None


@dataclass(frozen=True)
class ParserConfig:
    parser: type[ConfigurationParser] = Default
    collapse: Optional[Union[bool, set]] = None
    collapse_inverse: Optional[bool] = None
    separator: Optional[tuple[str]] = None
    comment_prefixes: Optional[tuple[str]] = None

    def create_parser(self, options: Optional[ParserOptions] = None) -> ConfigurationParser:
        kwargs = {}

        for field_name in ["collapse", "collapse_inverse", "separator", "comment_prefixes"]:
            value = getattr(options, field_name, None) or getattr(self, field_name)
            if value:
                kwargs.update({field_name: value})

        return self.parser(**kwargs)


MATCH_MAP: dict[str, ParserConfig] = {
    "*/systemd/*": ParserConfig(SystemD),
    "*/sysconfig/network-scripts/ifcfg-*": ParserConfig(Default),
    "*/sysctl.d/*.conf": ParserConfig(Default),
    "*/xml/*": ParserConfig(Xml),
}

CONFIG_MAP: dict[tuple[str, ...], ParserConfig] = {
    "ini": ParserConfig(Ini),
    "xml": ParserConfig(Xml),
    "json": ParserConfig(Txt),
    "cnf": ParserConfig(Default),
    "conf": ParserConfig(Default, separator=(r"\s",)),
    "sample": ParserConfig(Txt),
    "systemd": ParserConfig(SystemD),
    "template": ParserConfig(Txt),
}

KNOWN_FILES: dict[str, type[ConfigurationParser]] = {
    "ulogd.conf": ParserConfig(Ini),
    "sshd_config": ParserConfig(Indentation, separator=(r"\s",)),
    "hosts.allow": ParserConfig(Default, separator=(":",), comment_prefixes=("#",)),
    "hosts.deny": ParserConfig(Default, separator=(":",), comment_prefixes=("#",)),
    "hosts": ParserConfig(Default, separator=(r"\s",)),
    "nsswitch.conf": ParserConfig(Default, separator=(":",)),
    "lsb-release": ParserConfig(Default),
    "catalog": ParserConfig(Xml),
}


def parse(path: Union[FilesystemEntry, TargetPath], hint: Optional[str] = None, *args, **kwargs) -> ConfigParser:
    """Parses the content of an ``path`` or ``entry`` to a dictionary.

    Args:
        path: The path to either a directory or file.
        hint: What kind of parser should be used.
        collapse: Whether it should collapse everything or just a certain set of keys.
        collapse_inverse: Invert the collapse function to collapse everything but the keys inside ``collapse``.
        separator: The separator that should be used for parsing.
        comment_prefixes: What is specified as a comment.

    Raises:
        FileNotFoundError: If the ``path`` is not a file.
    """

    if not path.is_file(follow_symlinks=True):
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
