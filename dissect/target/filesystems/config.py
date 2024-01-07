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
    """A special :class:`.Filesystem` class that allows you to browse and interact with configuration files
    as ``directories`` and ``files`` by parsing the file into key/value pairs.

    Depending on the ``value`` of a configuration file's ``key``, it will act like a ``directory`` or ``file``:
        * When the ``key`` contains sub-values (dictionary), it will act like a ``directory``.
        * Otherwise it will act like a ``file``.

    Examples:
        >>> fs = ConfigurationFilesystem(target, "/etc")
        >>> entry = fs.get("xattr.conf")
        <ConfigurationEntry path=/etc/xattr.conf value=<dissect.target.helpers.configutil.Default object at 0x115683280>
        >>> entry.listdir() # listed entries are the keys in the configuration file
        [...
        'system.posix_acl_access',
        'system.posix_acl_default',
        'trusted.SGI_ACL_DEFAULT',
        'trusted.SGI_ACL_FILE',
        ...]
        >>> entry.get("system.posix_acl_access") # returns the value of the key
        <ConfigurationEntry path=/etc/xattr.conf/system.posix_acl_access value=permissions>
        >>> entry.get("system.posix_acl_access").open().read() # returns the raw value of the key
        b'permissions\\n'

    """

    __type__: str = "META:configuration"

    def __init__(self, target: Target, path: str, **kwargs):
        super().__init__(**kwargs)
        self.root.top = target.fs.get(path)

    def _get_till_file(self, path: str, relentry: FilesystemEntry) -> tuple[list[str], FilesystemEntry]:
        """Searches for the file entry that is pointed to by ``path``.

        The ``path`` could contain ``key`` entries too, so it searches for the entry from
        the start of the path.

        Returns:
            A list of ``parts`` containing keys: [keys, into, the, file].
            And the resolved entry: Entry(filename)
        """
        entry = relentry or self.root

        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")

        if not path:
            return [], entry

        parts = path.split("/")

        for idx, part in enumerate(parts, start=1):
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
        """Retrieve a :class:`ConfigurationEntry` or :class:`.FilesystemEntry` relative to the root or ``relentry``.

        Raises:
            FileNotFoundError: if it could not find the entry.
        """
        parts, entry = self._get_till_file(path, relentry)

        if entry.is_dir():
            return entry

        entry = self._convert_entry(entry, *args, **kwargs)

        for part in parts:
            _prev_entry = entry
            entry = entry.get(part)
            if entry is None:
                raise FileNotFoundError(f"{part!r} not found in {_prev_entry}.")

        return entry

    def _convert_entry(
        self, file_entry: FilesystemEntry, *args, **kwargs
    ) -> Union[ConfigurationEntry, FilesystemEntry]:
        """Creates a :class:`ConfigurationEntry` from a ``file_entry``.

        If an error occurs during the parsing of the file contents,
        the original ``file_entry`` is returned.
        """
        entry = file_entry
        try:
            config_parser = parse(entry, *args, **kwargs)
            entry = ConfigurationEntry(self, entry.path, entry, config_parser)
        except ConfigurationParsingError:
            # If a parsing error gets created, it should return the `entry`
            log.debug("Error when parsing %s", entry.path)

        return entry


class ConfigurationEntry(FilesystemEntry):
    """A Special filesystem entry.

    Behaves like a ``directory`` when :attr:`parser_items` is a :class:`.ConfigurationParser` or a ``dict``.
    Behaves like a ``file`` otherwise.

    Attributes:
        parser_items: A dict-like object containing all configuration entries and values.
            In most cases this is either a :class:`.ConfigurationParser` or ``dict``.
            Otherwise, its the entry's value

    Examples:
        >>> fs = ConfigurationFilesystem(target, "/etc")
        >>> entry = fs.get("xattr.conf")
        <ConfigurationEntry path=/etc/xattr.conf value=<dissect.target.helpers.configutil.Default object at 0x115683280>
        >>> entry.listdir() # listed entries are the keys in the configuration file
        [...
        'system.posix_acl_access',
        'system.posix_acl_default',
        'trusted.SGI_ACL_DEFAULT',
        'trusted.SGI_ACL_FILE',
        ...]
        >>> entry.as_dict()
        {
            ...
            "system.posix_acl_access" : "...",
            ...
        }
        >>> entry.get("system.posix_acl_access") # returns the value of the key
        <ConfigurationEntry path=/etc/xattr.conf/system.posix_acl_access value=permissions>
        >>> entry.get("system.posix_acl_access").open().read() # returns the raw value of the key
        b'permissions\\n'
    """

    def __init__(
        self,
        fs: Filesystem,
        path: str,
        entry: FilesystemEntry,
        parser_items: Optional[Union[dict, ConfigurationParser, str, list]] = None,
    ) -> None:
        super().__init__(fs, path, entry)
        self.parser_items = parser_items

    def __getitem__(self, item: str) -> ConfigurationEntry:
        return self.parser_items[item]

    def __repr__(self) -> str:
        output = f"path={self.path}"

        if not isinstance(self.parser_items, dict):
            output += f" value={self.parser_items}"

        return f"<{self.__class__.__name__} {output}"

    def get(self, key, default: Optional[Any] = None) -> Union[ConfigurationEntry, Any, None]:
        """Gets the dictionary key that belongs to this entry using ``key``.
        Behaves like ``dictionary.get()``.

        Args:
            ``key``: A dictionary key that is inside :attr:`parser_items`.
            ``default``: The default value to return if ``key`` is not inside this entry.

        Returns:
            a :class:`ConfigurationEntry` when ``key`` is present, otherwise its ``default``.
        """
        # Check for path in config entry
        if not key:
            raise TypeError("key should be defined")

        if key in self.parser_items:
            return ConfigurationEntry(
                self.fs,
                fsutil.join(self.path, key, alt_separator=self.fs.alt_separator),
                self.entry,
                self.parser_items[key],
            )
        return default

    def _write_value_mapping(self, values: dict[str, Any], indentation_nr: int = 0) -> str:
        """Internal function to transform the ``values`` dictionary to a string representation.

        Args:
            values: A dictionary or its contents.
            indentation_nr: How much indentation this entry should receive.

        Returns:
            An indented string containing all the information inside ``values``.
        """
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
        """Open this :class:`ConfigurationEntry`.

        If :attr:`parser_items` is a :class:`.ConfigurationParser`,
        it will ``open`` the underlying entry.

        Returns:
            A file-like object holding a byte representation of :attr:`parser_items`.
        """
        if isinstance(self.parser_items, ConfigurationParser):
            # Currently trying to open the underlying entry
            return self.entry.open()

        output_data = self._write_value_mapping(self.parser_items)
        return io.BytesIO(bytes(output_data, "utf-8"))

    def iterdir(self) -> Iterator[str]:
        for entry in self.scandir():
            yield entry.name

    def scandir(self) -> Iterator[ConfigurationEntry]:
        """Return the items inside :attr:`parser_items` as ``ConfigurationEntries``."""
        if self.is_file():
            raise NotADirectoryError()

        for key, values in self.parser_items.items():
            yield ConfigurationEntry(self.fs, key, self.entry, values)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return not self.is_dir(follow_symlinks)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Returns whether this :class:`ConfigurationEntry` can be considered a directory."""
        # if self.parser_items has keys (thus sub-values), we can consider it a directory.
        return hasattr(self.parser_items, "keys")

    def is_symlink(self) -> bool:
        """Return whether this :class:`ConfigurationEntry` is a symlink or not.

        Returns:
            False, as ``ConfigurationEntries`` are never symlinks.
        """
        # ConfigurationEntries are already resolved, so are never symlinks.
        return False

    def exists(self, key: str) -> bool:
        """Return whether the underlying :class:`.FilesystemEntry` :attr:`entry` and
        supplied ``key`` exists inside this :class:`ConfigurationEntry`.

        Returns:
            Whether the ``entry`` and ``key`` exists
        """
        return self.entry.exists() and key in self.parser_items

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Returns the stat from the underlying :class:`.FilesystemEntry` :attr:`entry`."""
        return self.entry.stat(follow_symlinks)

    def lstat(self) -> fsutil.stat_result:
        """Returns the lstat from the underlying :class:`.FilesystemEntry` :attr:`entry`."""

        return self.entry.lstat()

    def as_dict(self) -> dict:
        """Returns :attr:`parser_items` as a dictionary."""
        if isinstance(self.parser_items, ConfigurationParser):
            return self.parser_items.parsed_data
        return self.parser_items
