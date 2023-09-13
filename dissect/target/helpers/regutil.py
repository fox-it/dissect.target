""" Registry related abstractions """
from __future__ import annotations

import fnmatch
import re
import struct
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, TextIO, Union

from dissect.regf import regf

from dissect.target.exceptions import (
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)

GLOB_INDEX_REGEX = re.compile(r"(^[^\\]*[*?[]|(?<=\\)[^\\]*[*?[])")
GLOB_MAGIC_REGEX = re.compile(r"[*?[]")

KeyType = Union[regf.IndexLeaf, regf.FastLeaf, regf.HashLeaf, regf.IndexRoot, regf.NamedKey]
"""The possible key types that can be returned from the registry."""

ValueType = Union[int, str, bytes, list[str]]
"""The possible value types that can be returned from the registry."""


class RegistryHive:
    """Base class for registry hives."""

    def root(self) -> RegistryKey:
        """Return the root key of the hive."""
        return self.key("")

    def key(self, key: str) -> RegistryKey:
        """Retrieve a registry key from a specific path.

        Args:
            key: A path to a registry key within this hive.

        Raises:
            RegistryKeyNotFoundError: If the registry key could not be found.
        """
        raise NotImplementedError()

    def keys(self, keys: Union[str, list[str]]) -> Iterator[RegistryKey]:
        """Retrieve all the registry keys in this hive from the given paths.

        Args:
            keys: A single path to find, or a list of paths to iterate over.
        """
        keys = [keys] if not isinstance(keys, list) else keys
        for key in keys:
            try:
                yield self.key(key)
            except RegistryError:
                pass


class RegistryKey:
    """Base class for registry keys.

    Args:
        hive: The registry hive to which this registry key belongs.
    """

    def __init__(self, hive: Optional[RegistryHive] = None):
        self.hive = hive

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.name}>"

    @property
    def ts(self) -> datetime:
        """Returns the last modified timestamp of this key."""
        return self.timestamp

    @property
    def name(self) -> str:
        """Returns the name of this key."""
        raise NotImplementedError()

    @property
    def class_name(self) -> str:
        """Returns the class name of this key."""
        raise NotImplementedError()

    @property
    def path(self) -> str:
        """Returns the path of this key."""
        raise NotImplementedError()

    @property
    def timestamp(self) -> datetime:
        """Returns the last modified timestamp of this key."""
        raise NotImplementedError()

    def get(self, key_path: str) -> RegistryKey:
        """Returns the RegistryKey pointed to by ``path``.

        Args:
            key_path: The path relative to this ``RegistryKey``.

        Returns:
            A relative ``RegistryKey``
        """
        key_path = key_path.strip("\\")
        if not key_path:
            return self

        key_path = "\\".join([self.path, key_path])
        return self.hive.key(key_path)

    def subkey(self, subkey: str) -> RegistryKey:
        """Returns a specific subkey from this key.

        Args:
            subkey: The name of the subkey to retrieve.

        Raises:
            RegistryKeyNotFoundError: If this key has no subkey with the requested name.
        """
        raise NotImplementedError()

    def subkeys(self) -> list[RegistryKey]:
        """Returns a list of subkeys from this key."""
        raise NotImplementedError()

    def value(self, value: str) -> RegistryValue:
        """Returns a specific value from this key.

        Args:
            value: The name of the value to retrieve.

        Raises:
            RegistryValueNotFoundError: If this key has no value with the requested name.
        """
        raise NotImplementedError()

    def values(self) -> list[RegistryValue]:
        """Returns a list of all the values from this key."""
        raise NotImplementedError()


class RegistryValue:
    """Base class for registry values.

    Args:
        hive: The registry hive to which this registry value belongs.
    """

    def __init__(self, hive: Optional[RegistryHive] = None):
        self.hive = hive

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.name}={self.value!r}>"

    @property
    def name(self) -> str:
        """Returns the name of this value."""
        raise NotImplementedError()

    @property
    def value(self) -> ValueType:
        """Returns the value of this value."""
        raise NotImplementedError()

    @property
    def type(self) -> int:
        """Returns the type of this value.

        Reference:
            - https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
        """
        raise NotImplementedError()


class VirtualHive(RegistryHive):
    """Virtual hive implementation."""

    def __init__(self):
        self._root = VirtualKey(self, "")

    def __repr__(self) -> str:
        return "<VirtualHive>"

    def make_keys(self, path: str) -> VirtualKey:
        """Create a key structure in this virtual hive from the given path.

        ``path`` must be a valid registry path to some arbitrary key in the registry. This method will traverse
        all the components of the path and create a key if it does not already exist.

        Example:
            The path ``test\\data\\something\\`` becomes::

                    "" <- root node
                    ├─ test
                    |  ├─ data
                    |  |  ├─ something

        Args:
            path: The registry path to create a key structure for.

        Returns:
            The :class:`VirtualKey` for the last path component.
        """
        path = path.strip("\\")
        key = self._root
        prev = None

        if not path:
            return key

        parts = path.split("\\")
        for i, part in enumerate(parts):
            try:
                prev = key
                key = key.subkey(part)
            except RegistryKeyNotFoundError:
                vkey = VirtualKey(self, "\\".join(parts[: i + 1]))
                prev.add_subkey(part, vkey)
                key = vkey

            # There was a bug with overlaying VirtualKeys on top of RegfKeys
            # In filesystem.py we solve this with layers, but this approach seems to work as well.
            # Basically, if we see that we're about to "overwrite" an existing key,
            # we copy it into a VirtualKey.
            if not isinstance(key, VirtualKey):
                vkey = VirtualKey(self, "\\".join(parts[: i + 1]))
                vkey.top = key
                prev.add_subkey(part, vkey)
                key = vkey

        return key

    def map_hive(self, path: str, hive: RegistryHive) -> None:
        """Map a different registry hive to a path in this registry hive.

        Future traversals to this path will continue from the root of the mapped hive.

        Args:
            path: The path at which to map the registry hive.
            hive: The hive to map to the path.
        """
        vkey = self.make_keys(path)
        vkey.top = hive.root()

    def map_key(self, path: str, key: RegistryKey) -> None:
        """Map an arbitrary :class:`RegistryKey` to a path in this hive.

        Args:
            path: The path at which to map the registry key.
            key: The :class:`RegistryKey` to map in this hive.
        """
        keypath, _, name = path.strip("\\").rpartition("\\")
        vkey = self.make_keys(keypath)
        vkey.add_subkey(name, key)

    def map_value(self, path: str, name: str, value: Union[ValueType, RegistryValue]) -> None:
        """Map an arbitrary value to a path and value name in this hive.

        Args:
            path: The path to the registry key that should hold the value.
            name: The name at which to store the value.
            value: The value to map to the specified location.
        """
        vkey = self.make_keys(path)
        vkey.add_value(name, value)

    def key(self, key: str) -> RegistryKey:
        path = key.strip("\\")
        vkey = self._root

        if not path:
            return vkey

        parts = path.split("\\")
        for part in parts:
            vkey = vkey.subkey(part)

        return vkey


class VirtualKey(RegistryKey):
    """Virtual key implementation."""

    def __init__(self, hive: RegistryHive, path: str, class_name: Optional[str] = None):
        self._path = path
        if not path.strip("\\"):
            self._name = "VROOT"
        else:
            self._name = path.split("\\")[-1]
        self._class_name = class_name
        self._values: dict[str, RegistryValue] = {}
        self._subkeys: dict[str, RegistryKey] = {}
        self.top: RegistryKey = None
        super().__init__(hive=hive)

    def __contains__(self, key: str) -> bool:
        return key.lower() in self._subkeys

    def add_subkey(self, name: str, key: str):
        """Add a subkey to this key."""
        self._subkeys[name.lower()] = key

    def add_value(self, name: str, value: Union[ValueType, RegistryValue]):
        """Add a value to this key."""
        if not isinstance(value, RegistryValue):
            value = VirtualValue(self.hive, name, value)
        self._values[name.lower()] = value

    @property
    def name(self) -> str:
        return self._name

    @property
    def class_name(self) -> str:
        return self._class_name

    @property
    def path(self) -> str:
        return self._path

    @property
    def timestamp(self) -> datetime:
        if self.top:
            return self.top.timestamp
        return None

    def subkey(self, subkey: str) -> RegistryKey:
        try:
            return self._subkeys[subkey.lower()]
        except KeyError:
            pass

        if self.top:
            try:
                return self.top.subkey(subkey)
            except RegistryKeyNotFoundError:
                pass

        raise RegistryKeyNotFoundError(subkey)

    def subkeys(self) -> list[RegistryKey]:  # Dict_values view
        res = {}

        for key in self._subkeys.values():
            res[key.name.lower()] = key

        if self.top:
            for key in self.top.subkeys():
                kn = key.name.lower()
                if kn in res:
                    continue
                res[kn] = key

        return res.values()

    def value(self, value: str) -> RegistryValue:
        try:
            return self._values[value.lower()]
        except KeyError:
            pass

        if self.top:
            try:
                return self.top.value(value)
            except RegistryValueNotFoundError:
                pass
        raise RegistryValueNotFoundError(value)

    def values(self) -> list[RegistryValue]:
        res = {}

        for value in self._values.values():
            res[value.name.lower()] = value

        if self.top:
            for value in self.top.values():
                vn = value.name.lower()
                if vn in res:
                    continue
                res[vn] = value

        return res.values()


class VirtualValue(RegistryValue):
    """Virtual value implementation."""

    def __init__(self, hive: RegistryHive, name: str, value: ValueType):
        self._name = name
        self._value = value
        super().__init__(hive=hive)

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> ValueType:
        return self._value

    @property
    def type(self) -> int:
        return None


class HiveCollection(RegistryHive):
    """Hive implementation that is backed by multiple hives.

    The idea here is that you can open multiple version of the same
    hive (one regular, one with .LOG replayed and one RegBack).
    When opening a key, it would (try to) open it on every hive and
    return them in a KeyCollection.
    """

    def __init__(self, hives: Optional[list[RegistryHive]] = None):
        self.hives = hives or []
        super().__init__()

    def __len__(self):
        return len(self.hives)

    def __iter__(self):
        return iter(self.hives)

    def __getitem__(self, index: int):
        return self.hives[index]

    def add(self, hive: RegistryHive) -> None:
        self.hives.append(hive)

    def key(self, key: str) -> KeyCollection:
        res = KeyCollection()

        for hive in self:
            try:
                res.add(hive.key(key))
            except RegistryKeyNotFoundError:
                pass

        if not res:
            raise RegistryKeyNotFoundError(key)

        return res

    def keys(self, keys: Union[list, str]) -> Iterator[RegistryKey]:
        keys = [keys] if not isinstance(keys, list) else keys
        for key in keys:
            try:
                for sub in self.key(key):
                    yield sub
            except RegistryError:
                pass

    def iterhives(self) -> Iterator[RegistryHive]:
        return iter(self.hives)


class KeyCollection(RegistryKey):
    """Key implementation that is backed by multiple keys.

    For example, both the current and the RegBack hive returned
    a key, but with different values. With a KeyCollection it's
    possible to iterate over all versions of this key.

    Things like traversing down subkeys works as expected, going
    down every key in it's collection.
    """

    def __init__(self, keys: Optional[list[RegistryKey]] = None):
        self.keys = keys or []
        super().__init__()

    def __len__(self):
        return len(self.keys)

    def __iter__(self) -> Iterator[RegistryKey]:
        return iter(self.keys)

    def __getitem__(self, index) -> RegistryValue:
        return self.keys[index]

    def _key(self) -> RegistryKey:
        try:
            return self.keys[0]
        except IndexError:
            raise RegistryKeyNotFoundError()

    def add(self, key: Union[KeyCollection, RegistryKey]):
        if isinstance(key, KeyCollection):
            self.keys.extend(key.keys)
        else:
            self.keys.append(key)

    @property
    def class_name(self) -> str:
        return self._key().class_name

    @property
    def name(self) -> str:
        return self._key().name

    @property
    def path(self) -> str:
        return self._key().path

    @property
    def timestamp(self) -> datetime:
        return self._key().timestamp

    def get(self, key_path: str) -> KeyCollection:
        ret = KeyCollection()
        for key in self:
            try:
                ret.add(key.get(key_path))
            except RegistryKeyNotFoundError:
                pass

        if not ret:
            raise RegistryKeyNotFoundError(key_path)

        return ret

    def subkey(self, subkey: str) -> KeyCollection:
        ret = KeyCollection()
        for key in self:
            try:
                ret.add(key.subkey(subkey))
            except RegistryKeyNotFoundError:
                pass

        if not ret:
            raise RegistryKeyNotFoundError(subkey)

        return ret

    def subkeys(self) -> list[KeyCollection]:
        ret = defaultdict(KeyCollection)
        for key in self:
            for sub in key.subkeys():
                ret[sub.name].add(sub)

        return ret.values()

    def value(self, value: str) -> ValueCollection:
        ret = ValueCollection()
        for key in self:
            try:
                ret.add(key.value(value))
            except RegistryValueNotFoundError:
                pass

        if not ret:
            raise RegistryValueNotFoundError(value)

        return ret

    def values(self) -> list[ValueCollection]:
        ret = defaultdict(ValueCollection)
        for key in self:
            for value in key.values():
                ret[value.name].add(value)

        return ret.values()


class ValueCollection(RegistryValue):
    """Value implementation that is backed by multiple values.

    Same idea as KeyCollection, but for values.
    """

    def __init__(self, values: Optional[list[RegistryValue]] = None):
        self.values = values or []
        super().__init__()

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)

    def _value(self) -> RegistryValue:
        try:
            return self.values[0]
        except IndexError:
            raise RegistryValueNotFoundError()

    def add(self, value: RegistryValue) -> None:
        self.values.append(value)

    @property
    def name(self) -> str:
        return self._value().name

    @property
    def value(self) -> ValueType:
        return self._value().value

    @property
    def type(self) -> int:
        return self._value().type


class RegfHive(RegistryHive):
    """Registry implementation for regf hives."""

    def __init__(self, filepath: Path, fh: Optional[BinaryIO] = None):
        fh = fh or filepath.open("rb")
        self.hive = regf.RegistryHive(fh)
        self.filepath = filepath

    def root(self) -> RegistryKey:
        return RegfKey(self, self.hive.root())

    def key(self, key: str) -> RegistryKey:
        try:
            return RegfKey(self, self.hive.open(key))
        except regf.RegistryKeyNotFoundError as e:
            raise RegistryKeyNotFoundError(key, cause=e)


class RegfKey(RegistryKey):
    """Key implementation for regf keys."""

    def __init__(self, hive: RegistryHive, key: KeyType):
        self.key = key
        super().__init__(hive=hive)

    @property
    def name(self) -> str:
        return self.key.name

    @property
    def class_name(self) -> str:
        return self.key.class_name

    @property
    def path(self) -> str:
        return self.key.path

    @property
    def timestamp(self) -> datetime:
        return self.key.timestamp

    def subkey(self, subkey: str) -> RegistryKey:
        try:
            return RegfKey(self.hive, self.key.subkey(subkey))
        except regf.RegistryKeyNotFoundError as e:
            raise RegistryKeyNotFoundError(subkey, cause=e)

    def subkeys(self) -> list[RegistryKey]:
        return [RegfKey(self.hive, k) for k in self.key.subkeys()]

    def value(self, value: str) -> RegistryValue:
        try:
            return RegfValue(self.hive, self.key.value(value))
        except regf.RegistryValueNotFoundError as e:
            raise RegistryValueNotFoundError(value, cause=e)

    def values(self) -> list[RegistryValue]:
        return [RegfValue(self.hive, v) for v in self.key.values()]


class RegfValue(RegistryValue):
    """Value implementation for regf values."""

    def __init__(self, hive: RegistryHive, kv: RegistryValue):
        self.kv = kv
        super().__init__(hive=hive)

    @property
    def name(self) -> str:
        return self.kv.name

    @property
    def value(self) -> ValueType:
        return self.kv.value

    @property
    def type(self) -> int:
        return self.kv.type


class RegFlex:
    """A parser for text registry dumps (.reg files)."""

    def __init__(self):
        self.hives: dict[str, RegFlexHive] = {}

    def map_definition(self, fh: TextIO) -> None:
        """Parse a text registry export to a hive with keys and values.

        Args:
            fh: A file-like object opened in text mode of the registry export to parse.
        """
        vkey: RegFlexKey = None
        vhive: RegFlexHive = None

        for line in fh:
            line = line.strip()
            if not line:
                continue

            if line.startswith("[") and line.endswith("]"):
                if vkey:
                    vhive.map_key(vkey.path, vkey)

                hive, _, path = line[1:-1].partition("\\")
                hive = hive.upper()
                if hive not in self.hives:
                    self.hives[hive] = RegFlexHive()

                vhive = self.hives[hive]
                vkey = RegFlexKey(vhive, path)
                continue

            if line.startswith('"'):
                name, _, value = line.partition("=")
                name = name.strip('"')

                if value.endswith("\\"):
                    value = [value[:-1]]
                    while True:
                        next_line = next(fh).strip()
                        if next_line.endswith("\\"):
                            value.append(next_line[:-1])
                        else:
                            value.append(next_line)
                            break
                    value = "".join(value)

                vkey.add_value(name, RegFlexValue(vhive, name, value))

        vhive.map_key(vkey.path, vkey)


class RegFlexHive(VirtualHive):
    pass


class RegFlexKey(VirtualKey):
    pass


class RegFlexValue(VirtualValue):
    def __init__(self, hive: RegistryHive, name: str, value: ValueType):
        self._parsed_value = None
        super().__init__(hive, name, value)

    @property
    def value(self) -> ValueType:
        if not self._parsed_value:
            self._parsed_value = parse_flex_value(self._value)
        return self._parsed_value


def parse_flex_value(value: str) -> ValueType:
    """Parse values from text registry exports.

    Args:
        value: The value to parse.

    Raises:
        NotImplementedError: If ``value`` is not of a supported type for parsing.
    """
    if value.startswith('"'):
        return value.strip('"')

    vtype, _, value = value.partition(":")
    if vtype == "dword":
        return struct.unpack(">i", bytes.fromhex(value))[0]
    elif "hex" in vtype:
        value = bytes.fromhex(value.replace(",", ""))
        if vtype == "hex":
            return value

        # hex(T)
        # These values match regf type values
        vtype = int(vtype[4:5], 16)
        if vtype == regf.REG_NONE:
            return value if value else None
        elif vtype == regf.REG_SZ:
            return regf.try_decode_sz(value)
        elif vtype == regf.REG_EXPAND_SZ:
            return regf.try_decode_sz(value)
        elif vtype == regf.REG_BINARY:
            return value
        elif vtype == regf.REG_DWORD:
            return struct.unpack("<I", value)[0]
        elif vtype == regf.REG_DWORD_BIG_ENDIAN:
            return struct.unpack(">I", value)[0]
        elif vtype == regf.REG_MULTI_SZ:
            d = BytesIO(value)

            r = []
            while d.tell() < len(value):
                s = regf.read_null_terminated_wstring(d)
                if s == "":
                    break

                r.append(s)

            return r
        elif vtype == regf.REG_QWORD:
            return struct.unpack(">Q", value)[0]
        else:
            raise NotImplementedError(f"Registry flex value type {vtype}")


def has_glob_magic(pattern: str) -> bool:
    """Return whether ``pattern`` contains any glob patterns

    Args:
        pattern: The string to check on glob patterns.

    Returns:
        Whether ``pattern`` contains any glob patterns.
    """
    return GLOB_MAGIC_REGEX.search(pattern) is not None


def glob_split(pattern: str) -> tuple[str]:
    """Split a key path with glob patterns on the first key path part with glob patterns

    Args:
        pattern: A key path with glob patterns to split.

    Returns:
        A tuple of two strings, where the first contains the first number of
        key path parts (if any) which don't have a glob pattern. The second
        contains the rest of the key path with parts containing glob patterns.
    """
    first_glob = GLOB_INDEX_REGEX.search(pattern)

    if not first_glob:
        return pattern, ""

    pos = first_glob.start()
    return pattern[:pos], pattern[pos:]


def glob_ext(key_collection: KeyCollection, pattern: str) -> Iterator[KeyCollection]:
    """Yield all subkeys of ``key_collection`` that match the glob ``pattern``

    Args:
        key_collection: The ``KeyCollection`` to start the path pattern glob matching on.
        pattern: A key path with glob patterns.

    Yields:
        All subkeys that match ``pattern``
    """
    # This function operates by recursively stripping the last key path part
    # from pattern and recursively resolving the remaining part.

    if not has_glob_magic(pattern):
        # Short-cut if the pattern does not contain any actual globs.
        yield from glob_ext0(key_collection, pattern)
        return

    # The path pattern is stripped one key path part at a time for as long as
    # key_path contains glob patterns, starting at the end of the path.
    # At the final strip, key_path will be empty an last_key will contain the
    # very first part of the path pattern.
    key_path, _, last_key = pattern.strip("\\").rpartition("\\")

    if not key_path:
        # The end of the path is reached and the last key path part has glob
        # patterns (otherwise the shortcut at the start of the function would
        # have been taken).
        yield from glob_ext1(key_collection, last_key)
        return

    if has_glob_magic(key_path):
        # strip the next last key path part
        key_collections = glob_ext(key_collection, key_path)
    else:
        # This condition will generally not be true when the caller uses
        # glob_split() before calling this function (as
        # RegistryPlugin.glob_ext() does). In that case pattern (and thus
        # key_path), will start with a globbed path part.
        #
        # But if it is true, the key_path will not have any glob patterns, as
        # they were stripped off in the last path part (in last_key). So as a
        # short-cut the remaining key_path can be resolved directly instead of
        # recursively.
        key_collections = glob_ext0(key_collection, key_path)

    if has_glob_magic(last_key):
        glob_in_key_path = glob_ext1
    else:
        glob_in_key_path = glob_ext0

    for key_collection in key_collections:
        yield from glob_in_key_path(key_collection, last_key)


def glob_ext0(key_collection: KeyCollection, key_path: str) -> Iterator[KeyCollection]:
    """Yield the subkey given by ``key_path`` relative to ``key_collection``

    Args:
        key_collection: The ``KeyCollection`` to yield the subkey from.
        key_path: The key path to the subkey, relative to ``key_collection``.

    Yields:
        The subkey from ``key_collection`` pointed to by ``key_path``.
    """
    try:
        yield key_collection.get(key_path)
    except RegistryKeyNotFoundError:
        pass


def glob_ext1(key_collection: KeyCollection, pattern: str) -> Iterator[KeyCollection]:
    """Yield all subkeys from ``key_collection`` which match the glob pattern ``pattern``

    Args:
        key_collection: The ``KeyCollection`` from which subkeys should be matched.
        pattern: The pattern a subkey must match.

    Yields:
        All KeyCollections of subkeys that match ``pattern``.
    """
    subkeys = key_collection.subkeys()
    # Note that the Windows registry is case insensitive, while
    # fnmatch.fnmatch() may not be on certain systems.
    pattern = pattern.lower()

    for subkey in subkeys:
        if fnmatch.fnmatch(subkey.name.lower(), pattern):
            yield subkey
