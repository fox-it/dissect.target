from dissect.target.exceptions import PluginError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

RegistryKeyRecord = TargetRecordDescriptor(
    "windows/registry/regf/key",
    [
        ("datetime", "ts"),
        ("string", "path"),
        ("string", "key"),
        ("string", "source"),
    ],
)


RegistryValueRecord = TargetRecordDescriptor(
    "windows/registry/regf/value",
    [
        ("datetime", "ts"),
        ("string", "path"),
        ("string", "key"),
        ("string", "name"),
        ("dynamic", "value"),  # flow loophole
        ("varint", "data_type"),
        ("string", "source"),
    ],
)


class RegfPlugin(Plugin):
    """Regf dump plugin."""

    def check_compatible(self):
        try:
            self.target.registry.root()
        except PluginError:
            raise UnsupportedPluginError("Registry plugin not loaded")

    @export(record=[RegistryKeyRecord, RegistryValueRecord])
    def regf(self):
        """Return all registry keys and values.

        The Windows Registry is a hierarchical database that stores low-level settings for the Windows operating system
        and for applications that opt to use it.

        Sources:
            - https://en.wikipedia.org/wiki/Windows_Registry

        Yields RegistryKeyRecords and RegistryValueRecords

        RegistryKeyRecord fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified time.
            path (string): The key path.
            key (string): The key name.
            source (string): The hive file path.

        RegistryValueRecord fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified time.
            path (string): The key path.
            key (string): The key name.
            name (string): The value name.
            value (string): The value.
            source (string): The hive file path.
        """
        self.target.registry.load_user_hives()
        mappings = self.target.registry.mappings()

        for name, hive, path in self.target.registry.iterhives():
            if name in mappings:
                name = mappings[name]
            elif name.startswith("S-"):
                # Bit of a nasty hack
                name = f"HKEY_USERS\\{name}"

            for entry in self.walk(hive.root(), name, path):
                yield entry

    def walk(self, key, parent, path):
        yield RegistryKeyRecord(
            ts=key.timestamp,
            path=parent,
            key=key.name,
            source=path,
            _target=self.target,
        )

        for value in key.values():
            yield RegistryValueRecord(
                ts=key.timestamp,
                path=parent,
                key=key.name,
                name=value.name,
                value=value.value,
                data_type=value.type,
                source=path,
                _target=self.target,
            )

        for subkey in key.subkeys():
            n_parent = f"{parent}\\{subkey.name}"
            for item in self.walk(subkey, n_parent, path):
                yield item
