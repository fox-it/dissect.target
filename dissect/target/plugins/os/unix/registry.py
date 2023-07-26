from __future__ import annotations
from dissect.target import Target
from dissect.target.plugin import Plugin
from dissect.target.helpers import fsutil
from dissect.target.filesystem import Filesystem, FilesystemEntry
from configparser import RawConfigParser
import io


from typing import Any, Union


class UnixRegistryPlugin(Plugin):
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


class UnixRegistry(Filesystem):
    __fstype__: str = "META:registry"

    def __init__(self, target: Target, **kwargs):
        super().__init__(None, **kwargs)
        self.root = target.fs.get("/etc")

    def get(self, path: str, relentry=None) -> Union[FilesystemEntry, ConfigurationEntry]:
        entry = relentry or self.root

        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")
        if not path:
            return entry

        for part in path.split("/"):
            if entry.is_symlink():
                entry = entry.readlink_ext()

            if part == "..":
                entry = entry.up
                if not entry:
                    entry = self.root
            else:
                entry = entry.get(part)
                if entry.is_file():
                    try:
                        entry = ConfigurationEntry(self, path, entry)
                    except Exception:
                        # Couldn't parse the file.
                        ...
        return entry


class ConfigurationEntry(FilesystemEntry):
    def __init__(self, fs: Filesystem, path: str, entry: Any) -> None:
        super().__init__(fs, path, entry)

        self.parser_items = self.parse_config(entry)

    def parse_config(self, entry) -> RawConfigParser:
        if isinstance(entry, FilesystemEntry):
            parser = RawConfigParser(strict=False)
            parser.optionxform = str
            with entry.open() as fp:
                parser.readfp(fp)
                return parser

        return entry

    def get(self, path: str) -> ConfigurationEntry:
        # Check for path in config entry
        if self.is_dir():
            return ConfigurationEntry(self.fs, path, self.parser_items[path])
        raise NotADirectoryError("Cannot open a 'File' on a value")

    def open(self):
        # Return fh for path if entry is a file
        # Return bytes of value if entry is ConfigurationEntry
        if self.is_dir():
            raise IsADirectoryError("Cannot open a directory.")
        return io.BytesIO(self.parser_items)

    def iterdir(self):
        # Return dict keys
        if self.is_file():
            raise NotADirectoryError()
        yield from self.parser_items.keys()

    def scandir(self):
        # Return ConfigurationEntry of dict keys
        yield from self.iterdir()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return not self.is_dir()

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return isinstance(self.entry, dict)
