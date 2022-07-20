""" Registry related abstractions """

import binascii
import struct
from collections import defaultdict
from io import BytesIO

from dissect.regf import regf
from dissect.target.exceptions import (
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)


class RegistryHive:
    """Base class for registry hives."""

    def root(self):
        """Return the root of the hive."""
        return self.key("")

    def key(self, key):
        """Return the key at the specified location."""
        raise NotImplementedError()

    def keys(self, keys):
        """Iterate a number of keys."""
        keys = [keys] if not isinstance(keys, list) else keys
        for key in keys:
            try:
                yield self.key(key)
            except RegistryError:
                pass


class RegistryKey:
    """Base class for registry keys."""

    def __init__(self, hive=None):
        self.hive = hive

    @property
    def ts(self):
        """Returns the last modified timestamp of this key."""
        return self.timestamp

    @property
    def name(self):
        """Returns the name of this key."""
        raise NotImplementedError()

    @property
    def path(self):
        """Returns the path of this key."""
        raise NotImplementedError()

    @property
    def timestamp(self):
        """Returns the last modified timestamp of this key."""
        raise NotImplementedError()

    def subkey(self, subkey):
        """Returns the specified subkey from this key."""
        raise NotImplementedError()

    def subkeys(self):
        """Returns a list of subkeys from this key."""
        raise NotImplementedError()

    def value(self, value):
        """Returns the specified value from this key."""
        raise NotImplementedError()

    def values(self):
        """Returns a list of values from this key."""
        raise NotImplementedError()

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name}>"


class RegistryValue:
    """Base class for registry values."""

    def __init__(self, hive=None):
        self.hive = hive

    @property
    def name(self):
        """Returns the name of this value."""
        raise NotImplementedError()

    @property
    def value(self):
        """Returns the value of this value."""
        raise NotImplementedError()

    @property
    def type(self):
        """Returns the type of this value."""
        raise NotImplementedError()

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name}={self.value!r}>"


class VirtualHive(RegistryHive):
    """Virtual hive implementation."""

    def __init__(self):
        self._root = VirtualKey(self, "VROOT")
        self._root.hive = self

    def make_keys(self, path):
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

    def map_hive(self, path, hive):
        vkey = self.make_keys(path)
        vkey.top = hive.root()

    def map_key(self, path, key):
        keypath, _, name = path.strip("\\").rpartition("\\")
        vkey = self.make_keys(keypath)
        vkey.add_subkey(name, key)

    def map_value(self, path, name, value):
        vkey = self.make_keys(path)
        vkey.add_value(name, value)

    def root(self):
        return self._root

    def key(self, key):
        path = key.strip("\\")
        key = self._root

        if not path:
            return key

        parts = path.split("\\")
        for _, part in enumerate(parts):
            key = key.subkey(part)

        return key

    def __repr__(self):
        return "<VirtualHive>"


class VirtualKey(RegistryKey):
    """Virtual key implementation."""

    def __init__(self, hive, path):
        self._path = path
        self._name = path.split("\\")[-1]
        self._values = {}
        self._subkeys = {}
        self.top = None
        super().__init__(hive=hive)

    def __contains__(self, key):
        return key.lower() in self._subkeys

    def add_subkey(self, name, key):
        self._subkeys[name.lower()] = key

    def add_value(self, name, value):
        if not isinstance(value, RegistryValue):
            value = VirtualValue(self.hive, name, value)
        self._values[name.lower()] = value

    @property
    def timestamp(self):
        if self.top:
            return self.top.timestamp
        return None

    @property
    def name(self):
        return self._name

    @property
    def path(self):
        return self._path

    def subkey(self, subkey):
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

    def subkeys(self):
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

    def value(self, value):
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

    def values(self):
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

    def __init__(self, hive, name, value):
        self._name = name
        self._value = value
        super().__init__(hive=hive)

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    @property
    def type(self):
        return None


class HiveCollection(RegistryHive):
    """Hive implementation that is backed by multiple hives.

    The idea here is that you can open multiple version of the same
    hive (one regular, one with .LOG replayed and one RegBack).
    When opening a key, it would (try to) open it on every hive and
    return them in a KeyCollection.
    """

    def __init__(self, hives=None):
        self.hives = hives or []
        super().__init__()

    def __len__(self):
        return len(self.hives)

    def __iter__(self):
        return iter(self.hives)

    def __getitem__(self, index):
        return self.hives[index]

    def add(self, hive):
        self.hives.append(hive)

    def key(self, key):
        res = KeyCollection()

        for hive in self:
            try:
                res.add(hive.key(key))
            except RegistryKeyNotFoundError:
                pass

        if not res:
            raise RegistryKeyNotFoundError(key)

        return res

    def keys(self, keys):
        """Iterate values."""
        keys = [keys] if not isinstance(keys, list) else keys
        for key in keys:
            try:
                for sub in self.key(key):
                    yield sub
            except RegistryError:
                pass

    def iterhives(self):
        return iter(self.hives)


class KeyCollection(RegistryKey):
    """Key implementation that is backed by multiple keys.

    For example, both the current and the RegBack hive returned
    a key, but with different values. With a KeyCollection it's
    possible to iterate over all versions of this key.

    Things like traversing down subkeys works as expected, going
    down every key in it's collection.
    """

    def __init__(self, keys=None):
        self.keys = keys or []
        super().__init__()

    def __len__(self):
        return len(self.keys)

    def __iter__(self):
        return iter(self.keys)

    def __getitem__(self, index):
        return self.keys[index]

    def _key(self):
        try:
            return self.keys[0]
        except IndexError:
            raise RegistryKeyNotFoundError()

    def add(self, key):
        if isinstance(key, KeyCollection):
            self.keys.extend(key.keys)
        else:
            self.keys.append(key)

    @property
    def name(self):
        return self._key().name

    @property
    def path(self):
        return self._key().path

    @property
    def timestamp(self):
        return self._key().timestamp

    def subkey(self, subkey):
        ret = KeyCollection()
        for key in self:
            try:
                ret.add(key.subkey(subkey))
            except RegistryKeyNotFoundError:
                pass

        if not ret:
            raise RegistryKeyNotFoundError(subkey)

        return ret

    def subkeys(self):
        ret = defaultdict(KeyCollection)
        for key in self:
            for sub in key.subkeys():
                ret[sub.name].add(sub)

        return ret.values()

    def value(self, value):
        ret = ValueCollection()
        for key in self:
            try:
                ret.add(key.value(value))
            except RegistryValueNotFoundError:
                pass

        if not ret:
            raise RegistryValueNotFoundError(value)

        return ret

    def values(self):
        ret = defaultdict(ValueCollection)
        for key in self:
            for value in key.values():
                ret[value.name].add(value)

        return ret.values()


class ValueCollection(RegistryValue):
    """Value implementation that is backed by multiple values.

    Same idea as KeyCollection, but for values.
    """

    def __init__(self, values=None):
        self.values = values or []
        super().__init__()

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        return iter(self.values)

    def _value(self):
        try:
            return self.values[0]
        except IndexError:
            raise RegistryValueNotFoundError()

    def add(self, value):
        self.values.append(value)

    @property
    def name(self):
        return self._value().name

    @property
    def value(self):
        return self._value().value

    @property
    def type(self):
        return self._value().type


class RegfHive(RegistryHive):
    """Registry implementation for regf hives."""

    def __init__(self, filepath, fh=None):
        fh = fh or filepath.open()
        self.hive = regf.RegistryHive(fh)
        self.filepath = filepath

    def root(self):
        return RegfKey(self, self.hive.root())

    def key(self, key):
        try:
            return RegfKey(self, self.hive.open(key))
        except regf.RegistryKeyNotFoundError as e:
            raise RegistryKeyNotFoundError(key, cause=e)


class RegfKey(RegistryKey):
    """Key implementation for regf keys."""

    def __init__(self, hive, key):
        self.key = key
        super().__init__(hive=hive)

    @property
    def name(self):
        return self.key.name

    @property
    def path(self):
        return self.key.path

    @property
    def timestamp(self):
        return self.key.timestamp

    def subkey(self, subkey):
        try:
            return RegfKey(self.hive, self.key.subkey(subkey))
        except regf.RegistryKeyNotFoundError as e:
            raise RegistryKeyNotFoundError(subkey, cause=e)

    def subkeys(self):
        return [RegfKey(self.hive, k) for k in self.key.subkeys()]

    def value(self, value):
        try:
            return RegfValue(self.hive, self.key.value(value))
        except regf.RegistryValueNotFoundError as e:
            raise RegistryValueNotFoundError(value, cause=e)

    def values(self):
        return [RegfValue(self.hive, v) for v in self.key.values()]


class RegfValue(RegistryValue):
    """Value implementation for regf values."""

    def __init__(self, hive, kv):
        self.kv = kv
        super().__init__(hive=hive)

    @property
    def name(self):
        return self.kv.name

    @property
    def value(self):
        return self.kv.value

    @property
    def type(self):
        return self.kv.type


class RegFlex:
    def __init__(self):
        self.hives = {}

    def map_definition(self, fh):
        vkey = None
        vhive = None

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
                vkey = RegFlexKey(path)
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

                vkey.add_value(name, RegFlexValue(name, value))

        vhive.map_key(vkey.path, vkey)


class RegFlexHive(VirtualHive):
    pass


class RegFlexKey(VirtualKey):
    pass


class RegFlexValue(VirtualValue):
    def __init__(self, name, value):
        self._parsed_value = None
        super().__init__(name, value)

    @property
    def value(self):
        if not self._parsed_value:
            self._parsed_value = parse_flex_value(self._value)
        return self._parsed_value


def parse_flex_value(value):
    """Parse values from text registry dumps."""
    if value.startswith('"'):
        return value.strip('"')

    vtype, _, value = value.partition(":")
    if vtype == "dword":
        return struct.unpack(">i", binascii.unhexlify(value))[0]
    elif "hex" in vtype:
        value = binascii.unhexlify(value.replace(",", ""))
        if vtype == "hex":
            return value

        # hex(T)
        # These values match regf type values
        vtype = int(vtype[4:5], 16)
        if vtype == regf.REG_NONE:
            return value if value else None
        elif vtype == regf.REG_EXPAND_SZ:
            return regf.try_decode_sz(value)
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
            return struct.unpack(">q", value)[0]
        else:
            raise NotImplementedError(f"Registry flex value type {vtype}")
