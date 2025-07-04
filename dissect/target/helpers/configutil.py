from __future__ import annotations

import io
import json
import logging
import re
import sys
from collections import deque
from collections.abc import ItemsView, Iterable, Iterator, KeysView
from configparser import ConfigParser, MissingSectionHeaderError
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Literal,
    TextIO,
)

from defusedxml import ElementTree

from dissect.target.exceptions import ConfigurationParsingError, FileNotFoundError
from dissect.target.helpers.utils import to_list

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

    from typing_extensions import Self

try:
    from ruamel.yaml import YAML

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    if sys.version_info < (3, 11):
        import tomli as toml
    else:
        # tomllib is included since python 3.11
        import tomllib as toml  # novermin

    HAS_TOML = True
except ImportError:
    HAS_TOML = False


log = logging.getLogger(__name__)


def _update_dictionary(current: dict[str, Any], key: str, value: Any) -> None:
    if (prev_value := current.get(key)) is not None:  #  "" is a value
        if isinstance(prev_value, dict) and isinstance(value, dict):
            prev_value.update(value)
            return

        if isinstance(prev_value, str):
            prev_value = [prev_value]

        if isinstance(prev_value, list):
            # We want to append ``value`` to prev_value
            prev_value.append(value)

    current[key] = prev_value or value


class PeekableIterator:
    # https://more-itertools.readthedocs.io/en/stable/_modules/more_itertools/more.html#peekable

    def __init__(self, iterable: Iterable[str]):
        self._iterator = iter(iterable)
        self._cache = deque()

    def __iter__(self) -> PeekableIterator:
        return self

    def __next__(self) -> str:
        if self._cache:
            return self._cache.popleft()

        return next(self._iterator)

    def peek(self) -> str | None:
        if not self._cache:
            try:
                self._cache.append(next(self._iterator))
            except StopIteration:
                return None
        return self._cache[0]


class ConfigurationParser:
    """A configuration parser where you can configure certain aspects of the parsing mechanism.

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
        collapse: bool | Iterable[str] = False,
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

    def __getitem__(self, item: Any) -> dict | str:
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
        raise NotImplementedError

    def get(self, item: str, default: Any | None = None) -> Any:
        return self.parsed_data.get(item, default)

    def read_file(self, fh: TextIO | io.BytesIO) -> None:
        """Parse a configuration file.

        Raises:
            ConfigurationParsingError: If any exception occurs during during the parsing process.
        """

        try:
            self.parse_file(fh)
        except Exception as e:
            raise ConfigurationParsingError(e.args) from e

        if self.collapse_all or self.collapse:
            self.parsed_data = self._collapse_dict(self.parsed_data)

        if not isinstance(self.parsed_data, dict):
            self.parsed_data = self._collapse_dict(self.parsed_data, False)

    def merge(self, other: ConfigurationParser) -> ConfigurationParser:
        """Merge the contents of another parser into this one.
        On conflict, the values of the other parser will be used.

        Args:
            other: The other parser to merge.

        Returns:
            The merged parser.
        """

        self._merge(self.parsed_data, other.parsed_data)
        return self

    def _merge(self, dict1: dict, dict2: dict) -> dict:
        for key, value2 in dict2.items():
            value1 = dict1.get(key)
            if value1 is None:
                # Result does not have key yet, add it
                dict1[key] = value2
                continue

            collapse = self.collapse_all or self._collapse_check(key)

            if collapse:
                if isinstance(value1, dict) and isinstance(value2, dict):
                    self._merge(value1, value2)  # There should only be one, merge both
                else:
                    dict1[key] = value2
            else:
                combined = to_list(value1) + to_list(value2)
                # An empty string clears the list of values for the current key
                # Possibly turn this into an option if other parsers require different behavior
                combined = combined[combined.index("") + 1 :] if "" in combined else combined
                dict1[key] = combined

        return dict1

    def keys(self) -> KeysView:
        return self.parsed_data.keys()

    def items(self) -> ItemsView:
        return self.parsed_data.items()


class Default(ConfigurationParser):
    """Parse a configuration file specified by ``separator`` and ``comment_prefixes``.

    This parser splits only on the first ``separator`` it finds:

    .. code-block::

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.SEPARATOR = re.compile(rf"\s*[{''.join(self.separator)}]\s*")
        self.COMMENTS = re.compile(rf"\s*[{''.join(self.comment_prefixes)}]")
        self.skip_lines = (*self.comment_prefixes, "\n")

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
                information_dict[prev_key] = f"{prev_value} {line.strip()}"
                continue

            prev_key, *value = self.SEPARATOR.split(line, 1)
            value = value[0].strip() if value else ""

            _update_dictionary(information_dict, prev_key, value)

        self.parsed_data = information_dict


class CSVish(Default):
    """Parses CSV-ish config files (does not confirm to CSV standard!)."""

    def __init__(self, *args, fields: tuple[str, ...], **kwargs):
        self.fields = fields
        self.num_fields = len(self.fields)
        self.maxsplit = self.num_fields - 1
        super().__init__(*args, **kwargs)

    def parse_file(self, fh: TextIO) -> None:
        information_dict = {}

        for i, raw_line in enumerate(self.line_reader(fh, strip_comments=True)):
            line = raw_line.strip()
            columns = re.split(self.SEPARATOR, line, maxsplit=self.maxsplit)

            # keep unparsed lines separate (often env vars)
            data = {"line": line} if len(columns) < self.num_fields else dict(zip(self.fields, columns))

            information_dict[str(i)] = data

        self.parsed_data = information_dict


class Ini(ConfigurationParser):
    """Parses an ini file according using the built-in Python ``ConfigParser``."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.parsed_data = ConfigParser(
            strict=False,
            delimiters=self.separator,
            comment_prefixes=self.comment_prefixes,
            allow_no_value=True,
            interpolation=None,
        )
        self.parsed_data.optionxform = str

    def parse_file(self, fh: TextIO) -> None:
        offset = fh.tell()
        try:
            return self.parsed_data.read_file(fh)
        except MissingSectionHeaderError:
            pass

        fh.seek(offset)
        open_file = io.StringIO("[DEFAULT]\n" + fh.read())
        return self.parsed_data.read_file(open_file)


class Txt(ConfigurationParser):
    """Read the file into ``content``, and show the bumber of bytes read."""

    def parse_file(self, fh: TextIO) -> None:
        # Cast the size to a string, to print it out later.
        self.parsed_data = {"content": fh.read(), "size": str(fh.tell())}


class Bin(ConfigurationParser):
    """Read the file into ``binary`` and show the number of bytes read."""

    def parse_file(self, fh: io.BytesIO) -> None:
        self.parsed_data = {"binary": fh.read(), "size": str(fh.tell())}


class Xml(ConfigurationParser):
    """Parses an XML file. Ignores any constructor parameters passed from ``ConfigurationParser``."""

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
        if tree.text and (text := tree.text.strip(" \n\r")):
            result["text"] = text

        # if you need to store meta-data, you can extend add more entries here... CDATA, Comments, errors
        return {tree.tag: result} if root else result

    def _fix(self, content: str, position: tuple[int, int]) -> str:
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
            except ElementTree.ParseError as e:
                errors += 1
                document = self._fix(document, e.position)

        if not tree:
            # Error limit reached. Thus we consider the document not parseable.
            raise ConfigurationParsingError(f"Could not parse XML file: {fh.name} after {errors} attempts.")

        self.parsed_data = tree


class ListUnwrapper:
    """Provides utility functions to unwrap dictionary objects out of lists."""

    @staticmethod
    def unwrap(data: dict | list) -> dict | list:
        """Transforms a list with dictionaries to a dictionary.

        The order of the list is preserved. If no dictionary is found, the list remains untouched:

        .. code-block::

            ["value1", "value2"]    -> ["value1", "value2"]

            {"data": "value"}       -> {"data": "value"}

            [{"data": "value"}]     -> {
                                           "list_item0": {
                                                "data": "value"
                                           }
                                       }
        """
        orig = ListUnwrapper._unwrap_dict_list(data)
        return ListUnwrapper._unwrap_dict(orig)

    @staticmethod
    def _unwrap_dict(data: dict | list) -> dict | list:
        """Looks for dictionaries and unwraps its values."""

        if not isinstance(data, dict):
            return data

        root = {}
        for key, value in data.items():
            _value = ListUnwrapper._unwrap_dict_list(value)
            if isinstance(_value, dict):
                _value = ListUnwrapper._unwrap_dict(_value)
            root[key] = _value

        return root

    @staticmethod
    def _unwrap_dict_list(data: dict | list) -> dict | list:
        """Unwraps a list containing dictionaries."""
        if not isinstance(data, list) or not any(isinstance(obj, dict) for obj in data):
            return data

        return_value = {}
        for idx, elem in enumerate(data):
            return_value[f"list_item{idx}"] = elem

        return return_value


class Json(ConfigurationParser):
    """Parses a JSON file."""

    def parse_file(self, fh: TextIO) -> None:
        parsed_data = json.load(fh)
        self.parsed_data = ListUnwrapper.unwrap(parsed_data)


class Yaml(ConfigurationParser):
    """Parses a Yaml file."""

    def parse_file(self, fh: TextIO) -> None:
        if HAS_YAML:
            parsed_data = YAML(typ="safe").load(fh)
            self.parsed_data = ListUnwrapper.unwrap(parsed_data)
        else:
            raise ConfigurationParsingError("Failed to parse file, please install ruamel.yaml.")


class Toml(ConfigurationParser):
    """Parses a Toml file."""

    def parse_file(self, fh: TextIO) -> None:
        if HAS_TOML:
            self.parsed_data = toml.loads(fh.read())
        else:
            raise ConfigurationParsingError("Failed to parse file, please install tomli.")


class Env(ConfigurationParser):
    """Parses ``.env`` file contents according to Docker and bash specification.

    Does not apply interpolation of substituted values, e.g. ``foo=${bar}`` and does not attempt to parse list or dict
    strings. Does not support dynamic env files, e.g. ``foo=`bar```. Also does not support multi-line key/value
    assignments (yet).

    Resources:
        - https://docs.docker.com/compose/environment-variables/variable-interpolation/#env-file-syntax
        - https://github.com/theskumar/python-dotenv/blob/main/src/dotenv/parser.py
    """

    RE_KV = re.compile(r"^(?P<key>.+?)=(?P<value>(\".+?\")|(\'.+?\')|(.*?))?(?P<comment> \#.+?)?$")

    def __init__(self, comments: bool = True, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.comments = comments
        self.parsed_data: dict | tuple[dict, str | None] = {}

    def parse_file(self, fh: TextIO) -> None:
        for line in fh:
            # Blank lines are ignored.
            # Lines beginning with ``#`` are processed as comments and ignored.
            if not line or line[0] == "#" or "=" not in line:
                continue

            # Each line represents a key-value pair. Values can optionally be quoted.
            # Inline comments for unquoted values must be preceded with a space.
            # Value may be empty.
            match = self.RE_KV.match(line)

            # Line could be invalid
            if not match:
                log.warning("Could not parse line in %s: '%s'", fh, line)
                continue

            key = match.groupdict()["key"]
            value = match.groupdict().get("value") or ""
            value = value.strip()
            comment = match.groupdict().get("comment")
            comment = comment.replace(" # ", "", 1) if comment else None

            # Surrounding whitespace characters are removed, unless quoted.
            if value and ((value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")):
                is_quoted = True
                value = value.strip("\"'")
            else:
                is_quoted = False
                value = value.strip()

            # Unquoted values may start with a quote if they are properly escaped.
            if not is_quoted and value[:2] in ["\\'", '\\"']:
                value = value[1:]

            # Interpret boolean values
            if value.lower() in ["1", "true"]:
                value = True
            elif value.lower() in ["0", "false"]:
                value = False

            # Interpret integer values
            if isinstance(value, str) and re.match(r"^[0-9]{1,}$", value):
                value = int(value)

            if key.strip() in self.parsed_data:
                log.warning("Duplicate environment key '%s' in file %s", key.strip(), fh)

            self.parsed_data[key.strip()] = (value, comment) if self.comments else value


class ScopeManager:
    """A (context)manager for dictionary scoping.

    This class provides utility functions to keep track of scopes inside a dictionary.

    Attributes:
        _parents: A dictionary accounting what child belongs to which parent dictionary.
        _root: The initial dictionary.
        _current: The current dictionary.
        _previous: The node before the current (changed) node.
    """

    def __init__(self):
        self._parents = {}
        self._root = {}
        self._current = self._root
        self._previous = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.clean()

    def _set_prev(self, keep_prev: bool) -> None:
        """Set :attr:`_previous` before :attr:`_current` changes."""
        if not keep_prev:
            self._previous = self._current

    def push(self, name: str, keep_prev: bool = False) -> Literal[True]:
        """Push a new key to the :attr:`_current` dictionary and return that we did."""
        child = self._current.get(name)
        new_child = {}
        parent = self._current
        if isinstance(child, dict):
            # A second scope with the same name, turn the existing one into a list and append a new one
            parent[name] = [child, new_child]
            child = parent[name]
        elif isinstance(child, list):
            # Multiple scopes with the same name, append a new one to the list
            child.append(new_child)
        elif isinstance(child, str):
            # Child is not a scope but a scalar value, do nothing
            pass
        else:
            # Create a new scope
            parent[name] = new_child

        self._parents[id(new_child)] = parent
        self._set_prev(keep_prev)
        self._current = new_child
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

    .. code-block::

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
        next_line: str | None = None,
    ) -> bool:
        """A function to check whether to create a new scope, or go back to a previous one.

        Args:
            manager: A :class:`ScopeManager` that contains the logic to ``push`` and ``pop`` scopes. And keeps state.
            line: The line to be parsed.
            key: The key that should be updated during a :method:`ScopeManager.push`.
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

        .. code-block::

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
        next_line: str | None = None,
    ) -> bool:
        scope_char = ("[", "]")
        changed = False
        if line.lstrip().startswith(scope_char):
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
                        values=[*prev_values, continued_value],
                    )
                    continue

                manager.update(key, value)

            self.parsed_data = manager._root

    def _update_continued_values(
        self, func: Callable[[str, str], None], key: str, values: list[str]
    ) -> tuple[list, None]:
        value = " ".join(values)
        func(key, value)
        return [], None


@dataclass(frozen=True)
class ParserOptions:
    collapse: bool | set | None = None
    collapse_inverse: bool | None = None
    separator: tuple[str] | None = None
    comment_prefixes: tuple[str] | None = None


@dataclass(frozen=True)
class ParserConfig:
    parser: type[ConfigurationParser] = Default
    collapse: bool | set | None = None
    collapse_inverse: bool | None = None
    separator: tuple[str] | None = None
    comment_prefixes: tuple[str] | None = None
    fields: tuple[str] | None = None

    def create_parser(self, options: ParserOptions | None = None) -> ConfigurationParser:
        kwargs = {}

        for field_name in ["collapse", "collapse_inverse", "separator", "comment_prefixes", "fields"]:
            value = getattr(options, field_name, None) or getattr(self, field_name)
            if value:
                kwargs.update({field_name: value})

        return self.parser(**kwargs)


MATCH_MAP: dict[str, ParserConfig] = {
    "*/systemd/*": ParserConfig(SystemD),
    "*/sysconfig/network-scripts/ifcfg-*": ParserConfig(Default),
    "*/sysctl.d/*.conf": ParserConfig(Default),
    "*/xml/*": ParserConfig(Xml),
    "*.bashrc": ParserConfig(Txt),
    "*/vim/vimrc*": ParserConfig(Txt),
}

CONFIG_MAP: dict[tuple[str, ...], ParserConfig] = {
    "ini": ParserConfig(Ini),
    "xml": ParserConfig(Xml),
    "json": ParserConfig(Json),
    "yml": ParserConfig(Yaml),
    "yaml": ParserConfig(Yaml),
    "cnf": ParserConfig(Default),
    "conf": ParserConfig(Default, separator=(r"\s",)),
    "sample": ParserConfig(Txt),
    "sh": ParserConfig(Txt),
    "key": ParserConfig(Txt),
    "crt": ParserConfig(Txt),
    "pem": ParserConfig(Txt),
    "pl": ParserConfig(Txt),  # various admin panels
    "lua": ParserConfig(Txt),  # wireshark etc.
    "txt": ParserConfig(Txt),
    "systemd": ParserConfig(SystemD),
    "template": ParserConfig(Txt),
    "toml": ParserConfig(Toml),
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
    "ld.so.cache": ParserConfig(Bin),
    "fstab": ParserConfig(
        CSVish,
        separator=(r"\s",),
        comment_prefixes=("#",),
        fields=("device", "mount", "type", "options", "dump", "pass"),
    ),
    "crontab": ParserConfig(
        CSVish,
        separator=(r"\s",),
        comment_prefixes=("#",),
        fields=("minute", "hour", "day", "month", "weekday", "user", "command"),
    ),
    "shadow": ParserConfig(
        CSVish,
        separator=(r"\:",),
        comment_prefixes=("#",),
        fields=(
            "username",
            "password",
            "lastchange",
            "minpassage",
            "maxpassage",
            "warning",
            "inactive",
            "expire",
            "rest",
        ),
    ),
    "passwd": ParserConfig(
        CSVish,
        separator=(r"\:",),
        comment_prefixes=("#",),
        fields=("username", "password", "uid", "gid", "gecos", "homedir", "shell"),
    ),
    "mime.types": ParserConfig(CSVish, separator=(r"\s+",), comment_prefixes=("#",), fields=("name", "extensions")),
}


def parse(path: Path, hint: str | None = None, *args, **kwargs) -> ConfigurationParser:
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

    if not path.is_file():
        raise FileNotFoundError(f"Could not parse {path} as a dictionary.")

    options = ParserOptions(*args, **kwargs)

    return parse_config(path, hint, options)


def parse_config(
    entry: Path,
    hint: str | None = None,
    options: ParserOptions | None = None,
) -> ConfigurationParser:
    parser_type = _select_parser(entry, hint)

    parser = parser_type.create_parser(options)
    with entry.open("rb") as fh:
        open_file = io.TextIOWrapper(fh, encoding="utf-8") if not isinstance(parser, Bin) else io.BytesIO(fh.read())
        parser.read_file(open_file)

    if isinstance(parser, SystemD):
        return _parse_drop_files(entry, options, parser)

    return parser


def _parse_drop_files(path: Path, options: ParserOptions, main_parser: ConfigurationParser) -> ConfigurationParser:
    if not (drop_folder := path.with_name(path.name + ".d")).exists():
        return main_parser

    for drop_file in sorted(drop_folder.glob("*.conf")):
        if not drop_file.is_file():
            continue

        drop_file_parser = ParserConfig(SystemD).create_parser(options)
        with drop_file.open("r") as fh:
            drop_file_parser.read_file(fh)
            main_parser.merge(drop_file_parser)

    return main_parser


def _select_parser(path: Path, hint: str | None = None) -> ParserConfig:
    if hint and (parser_type := CONFIG_MAP.get(hint)):
        return parser_type

    for match, value in MATCH_MAP.items():
        if path.match(match):
            return value

    extention_parser = CONFIG_MAP.get(path.suffix.lstrip("."), ParserConfig(Default))
    return KNOWN_FILES.get(path.name, extention_parser)
