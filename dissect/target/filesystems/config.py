from __future__ import annotations

import io
import textwrap
from logging import getLogger
from typing import Any, BinaryIO, Iterator, Optional, Union

from dissect.target import Target
from dissect.target.exceptions import ConfigurationParsingError
from dissect.target.filesystem import Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.helpers.configutil import ConfigurationParser, parse

log = getLogger(__name__)


class ConfigurationFilesystem(VirtualFilesystem):
    """A special ``Filesystem`` that allows you to browse files as directories by parsing
    the file into key value pairs.

    The ``key`` are ``files`` if its ``value`` is not a dictionary,
    where they are ``directories`` if it is.

    This allows you to browse these ``files`` like you'd do on a filesystem.
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
        """Returns an entry pointed to by ``path``."""
        parts, entry = self._get_till_file(path, relentry)

        if entry.is_dir():
            return entry

        entry = self._convert_entry(entry, *args, **kwargs)

        for part in parts:
            entry = entry.get(part)

        return entry

    def _convert_entry(
        self, file_entry: FilesystemEntry, *args, **kwargs
    ) -> Union[ConfigurationEntry, FilesystemEntry]:
        """Creates a ``ConfigurationEntry`` from a ``file_entry``.

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
    def __init__(
        self,
        fs: Filesystem,
        path: str,
        entry: FilesystemEntry,
        parser_items: Optional[Union[dict, ConfigurationParser, Any]] = None,
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

    def get(self, key: Optional[str] = None, default: Optional[Any] = None) -> Union[ConfigurationEntry, Any]:
        """Gets the dictionary key that belongs to this entry using ``key``.

        This get is a bit special as it behaves as a ``dictionary.get``.
        Which means the ``default`` here is the value  it should return if it coould not find anything.

        Args:
            ``key``: A dictionary key that is inside ``self.parser_items``.
            ``default``: The default value to return if ``key`` is not inside this entry.

        Returns:
            a ``ConfigurationEntry`` if ``key`` was inside this keys contents, otherwise its ``default``.
        """
        # Check for path in config entry
        if not key:
            # Return self if configuration was found.
            return self

        if key in self.parser_items:
            return ConfigurationEntry(
                self.fs,
                fsutil.join(self.path, key, alt_separator=self.fs.alt_separator),
                self.entry,
                self.parser_items[key],
            )
        return default

    def _write_value_mapping(self, values: dict[str, Any], indentation_nr: int = 0) -> str:
        """Recursively write the ``values`` dictionary to an output with indentation for the values.

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
        """Returns the a byte representation of the ``self.parser_items``.

        In the case that ``parser_items`` is a ``ConfigurationParser`` it will open the raw entry
        without any parsing.

        Otherwise it creates a byte representation of the data inside ``parser_items``.
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
        """Return the items inside ``self.parser_items`` as ``ConfigurationEntries``."""
        if self.is_file():
            raise NotADirectoryError()

        for key, values in self.parser_items.items():
            yield ConfigurationEntry(self.fs, key, self.entry, values)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return not self.is_dir(follow_symlinks)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """If ``self.parser_items`` has the ``keys``, we see it as a directory."""
        return hasattr(self.parser_items, "keys")

    def is_symlink(self) -> bool:
        """The underlying entry should already be resolved, so we do not consider any of these entries
        symlinks.
        """
        return False

    def exists(self, key: str) -> bool:
        """The underlying entry should exists, an the ``key`` we profide should
        be a key inside our dictionary.

        Returns: Whether the entry exists or not.
        """
        return self.entry.exists() and key in self.parser_items

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Returns the stat from the underlying entry."""
        return self.entry.stat(follow_symlinks)

    def lstat(self) -> fsutil.stat_result:
        """Returns the lstat from the underlying entry."""

        return self.entry.lstat()

    def as_dict(self) -> dict:
        """Returns the underying dictionary or value that belongs to this Entry."""
        if isinstance(self.parser_items, ConfigurationParser):
            return self.parser_items.parsed_data
        return self.parser_items
