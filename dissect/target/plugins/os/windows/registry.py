from __future__ import annotations

import logging
import re
from collections import defaultdict
from functools import lru_cache
from typing import TYPE_CHECKING, Final

from dissect.target.exceptions import (
    HiveUnavailableError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.regutil import (
    HiveCollection,
    KeyCollection,
    RegfHive,
    RegistryHive,
    RegistryKey,
    RegistryValue,
    ValueCollection,
    VirtualHive,
    glob_ext,
    glob_split,
)
from dissect.target.plugin import Plugin, internal

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.helpers.record import WindowsUserRecord
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

CONTROLSET_REGEX = re.compile("CurrentControlSet", flags=re.IGNORECASE)


class RegistryPlugin(Plugin):
    """Provides registry access for Windows targets.

    Acts much the same to how the registry works on a live Windows machine.
    Hives are correctly mapped under e.g. HKLM\\SOFTWARE.

    Internal functions only.
    """

    __namespace__ = "registry"

    SHORTNAMES: Final[dict[str, str]] = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKCC": "HKEY_CURRENT_CONFIG",
        "HKCU": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
    }

    MAPPINGS: Final[dict[str, str]] = {
        "SAM": "HKEY_LOCAL_MACHINE\\SAM",
        "SECURITY": "HKEY_LOCAL_MACHINE\\SECURITY",
        "SOFTWARE": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "SYSTEM": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "COMPONENTS": "HKEY_LOCAL_MACHINE\\COMPONENTS",
        "DEFAULT": "HKEY_USERS\\.DEFAULT",
        "BCD": "HKEY_LOCAL_MACHINE\\BCD00000000",
        "ELAM": "HKEY_LOCAL_MACHINE\\ELAM",
    }

    SYSTEM = (
        "SAM",
        "SECURITY",
        "SOFTWARE",
        "SYSTEM",
        "COMPONENTS",
        "DEFAULT",
        "ELAM",
        "USER.DAT",  # Win 95/98/ME
        "SYSTEM.DAT",  # Win 95/98/ME
        "CLASSES.DAT",  # Win ME
        "REG.DAT",  # Win 3.1
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self._root = VirtualHive()
        self._hive_collections = defaultdict(HiveCollection)
        self._hive_paths = []

        self._hives_to_users: dict[RegfHive, UserDetails] = {}

        self._controlsets = []
        self._currentcontrolset = None
        self._users_loaded = False
        self._init_registry()

        self.key = lru_cache(4096)(self.key)

    def _init_registry(self) -> None:
        dirs = [
            # Windows XP or newer
            ("sysvol/windows/system32/config", False),
            # Windows NT3, NT4, 2k
            ("sysvol/WINNT/system32/config", False),
            # Windows 3.11, 95, 98, ME
            ("sysvol/windows", False),
            # ReactOS (alternative location)
            ("sysvol/reactos", False),
            # RegBack hives are often empty files
            ("sysvol/windows/system32/config/RegBack", True),
        ]
        opened_hives = set()

        for path, log_empty_to_debug in dirs:
            config_dir = self.target.fs.path(path)
            for fname in self.SYSTEM:
                hive_file = config_dir.joinpath(fname)
                if not hive_file.exists():
                    self.target.log.debug("Could not find hive: %s", hive_file)
                    continue

                if hive_file.stat().st_size == 0:
                    # Only log to debug if we have found a valid hive in a previous path
                    log_level = logging.DEBUG if log_empty_to_debug or fname in opened_hives else logging.WARNING
                    self.target.log.log(log_level, "Empty hive: %s", hive_file)
                    continue

                try:
                    hf = RegfHive(hive_file)
                    self._add_hive(fname, hf, hive_file)
                    opened_hives.add(fname)
                except Exception as e:
                    self.target.log.warning("Could not open hive: %s", hive_file)
                    self.target.log.debug("", exc_info=e)

        for drive in ["sysvol", "efi"]:
            bcd = self.target.fs.path(drive).joinpath("boot/BCD")
            if not bcd.exists():
                continue

            if bcd.stat().st_size == 0:
                self.target.log.warning("Empty BCD hive: %s", bcd)
                continue

            try:
                hf = RegfHive(bcd)
                self._add_hive("BCD", hf, bcd)
            except Exception as e:
                self.target.log.warning("Could not open BCD: %s", bcd)
                self.target.log.debug("", exc_info=e)

        for hive, location in self.MAPPINGS.items():
            if hive in self._hive_collections:
                self._map_hive(location, self._hive_collections[hive])

    def _init_users(self) -> None:
        # The initialization of user hives is separated from the initialization
        # of the class on purpose.
        # Loading user hives needs user information (through _os.users()),
        # while getting those users needs a minimal functional registry (the
        # HKLM hive should be available).
        if self._users_loaded:
            return

        for user_details in self.target.user_details.all_with_home():
            user = user_details.user
            ntuser = user_details.home_path.joinpath("ntuser.dat")

            if not ntuser.exists():
                self.target.log.debug("Could not find ntuser.dat: %s", ntuser)
            elif ntuser.stat().st_size == 0:
                self.target.log.warning("Empty NTUSER.DAT hive: %s", ntuser)
            else:
                try:
                    ntuserhive = RegfHive(ntuser)
                    self.add_hive(user.sid, f"HKEY_USERS\\{user.sid}", ntuserhive, ntuser)
                    self._hives_to_users[ntuserhive] = user_details
                except Exception as e:
                    self.target.log.warning("Could not open ntuser.dat: %s", ntuser)
                    self.target.log.debug("", exc_info=e)

            usrclass = user_details.home_path.joinpath("AppData/Local/Microsoft/Windows/usrclass.dat")

            if not usrclass.exists():
                self.target.log.debug("Could not find usrclass.dat: %s", usrclass)
            elif usrclass.stat().st_size == 0:
                self.target.log.warning("Empty UsrClass.DAT hive: %s", usrclass)
            else:
                try:
                    usr_class_hive = RegfHive(usrclass)
                    self.add_hive(f"{user.sid}_Classes", f"HKEY_USERS\\{user.sid}_Classes", usr_class_hive, usrclass)
                    self._map_hive(f"HKEY_USERS\\{user.sid}\\Software\\Classes", usr_class_hive)

                    self._hives_to_users[usr_class_hive] = user_details
                except Exception as e:
                    self.target.log.warning("Could not open usrclass.dat: %s", usrclass)
                    self.target.log.debug("", exc_info=e)

        self._users_loaded = True

    @internal
    def load_user_hives(self) -> None:
        """Load and map the user hives present in the target."""
        self._init_users()

    def _add_hive(self, name: str, hive: RegistryHive, path: TargetPath) -> None:
        """Add a hive to the internal _hive_collections and _hive_paths."""
        self._hive_collections[name.upper()].add(hive)
        self._hive_paths.append((name, hive, path))

    def _map_hive(self, location: str, hive: RegistryHive) -> None:
        """Map a hive to a specific location in the root hive."""
        self._root.map_hive(location, hive)

    @internal
    def add_hive(self, name: str, location: str, hive: RegistryHive, path: TargetPath) -> None:
        """Register and add a hive to a specific location in the root hive."""
        self._add_hive(name, hive, path)
        self._map_hive(location, hive)

    def check_compatible(self) -> None:
        if not len(self._hive_collections):
            raise UnsupportedPluginError("No hive collections found")

    @property
    def controlsets(self) -> list[str]:
        """Return a list of the different ControlSet names."""
        if not self._controlsets:
            for key in self.key("HKLM\\SYSTEM").subkeys():
                if key.name.startswith("ControlSet0"):
                    self._controlsets.append(key.name)
                if key.name == "Select":
                    current_value = key.value("Current").value
                    self._currentcontrolset = f"ControlSet{current_value:03d}"
        return self._controlsets

    @internal
    def root(self) -> KeyCollection:
        """Returns the root of the virtual registry."""
        return self.key()

    @internal
    def key(self, key: str | None = None) -> KeyCollection:
        """Query the virtual registry on the given key.

        Returns a KeyCollection which contains all keys that match
        the query.
        """
        key = (key or "").strip("\\")

        if not key:
            return KeyCollection([self._root.root()])

        if CONTROLSET_REGEX.findall(key):
            if not self._currentcontrolset:
                self.target.log.warning("No known destination for CurrentControlSet link")
                raise RegistryKeyNotFoundError(key)

            key = CONTROLSET_REGEX.sub(self._currentcontrolset, key, 1)

        hive, _, path = key.partition("\\")
        for short_name, name in self.SHORTNAMES.items():
            if hive.upper() == short_name.upper():
                hive = name
                break

        key = f"{hive}\\{path}"

        if hive in ("HKEY_CURRENT_USER", "HKEY_USERS"):
            self._init_users()

        if hive == "HKEY_CURRENT_USER":
            res = KeyCollection()
            for sid in self.key("HKEY_USERS").subkeys():
                if sid.name.endswith("_Classes"):
                    continue
                try:
                    res.add(self.key(f"HKEY_USERS\\{sid.name}\\{path}"))
                except RegistryKeyNotFoundError:
                    pass
            return res
        if hive == "HKEY_CLASSES_ROOT":
            res = self.key(f"HKEY_CURRENT_USER\\Software\\Classes\\{path}")
            res.add(self.key(f"HKEY_LOCAL_MACHINE\\Software\\Classes\\{path}"))
            return res
        res = self._root.key(key)

        if not isinstance(res, KeyCollection):
            res = KeyCollection([res])

        return res

    @internal
    def value(self, key: str, value: str) -> ValueCollection:
        """Convenience method for accessing a specific value."""
        return self.key(key).value(value)

    @internal
    def subkey(self, key: str, subkey: str) -> KeyCollection:
        """Convenience method for accessing a specific subkey."""
        return self.key(key).subkey(subkey)

    @internal
    def keys(self, keys: str | Iterable[str]) -> Iterator[RegistryKey]:
        """Yields all keys that match the given queries.

        Automatically resolves CurrentVersion keys. Also flattens KeyCollections.
        """
        keys = [keys] if isinstance(keys, str) else keys

        for key in self._iter_controlset_keypaths(keys):
            try:
                yield from self.key(key)
            except (RegistryKeyNotFoundError, HiveUnavailableError):  # noqa: PERF203
                pass

    @internal
    def values(self, keys: str | Iterable[str], value: str) -> Iterator[RegistryValue]:
        """Yields all values that match the given queries.

        Automatically resolves CurrentVersion keys. Also flattens ValueCollections.
        """

        for key in self.keys(keys):
            try:
                yield key.value(value)
            except RegistryValueNotFoundError:  # noqa: PERF203
                pass

    def _iter_controlset_keypaths(self, keys: Iterable[str]) -> Iterator[str]:
        """Yield the key transformed for the different control sets."""
        for key in keys:
            if not self.controlsets or not CONTROLSET_REGEX.search(key):
                yield key
                continue

            for controlset in self.controlsets:
                yield CONTROLSET_REGEX.sub(controlset, key)

    @internal
    def iterhives(self) -> Iterator[tuple[str, RegistryHive, TargetPath]]:
        """Returns an iterator for all hives.

        Items are tuples with three members: (name, hive, path)
        """
        return iter(self._hive_paths)

    @internal
    def mappings(self) -> dict[str, str]:
        """Return hive mappings."""
        return self.MAPPINGS

    @internal
    def get_user_details(self, key: RegistryKey | RegistryValue) -> UserDetails | None:
        """Return user details for the user who owns a registry hive that contains the provided key."""
        if not key.hive or not getattr(key.hive, "filepath", None):
            return None

        return self._hives_to_users.get(key.hive)

    @internal
    def get_user(self, key: RegistryKey | RegistryValue) -> WindowsUserRecord | None:
        """Return user record for the user who owns a registry hive that contains the provided key."""
        details = self._hives_to_users.get(key.hive)
        if details:
            return details.user
        return None

    @internal
    def glob_ext(self, pattern: str) -> Iterator[KeyCollection]:
        key_path, pattern = glob_split(pattern)

        try:
            key_collection = self.key(key_path)
        except RegistryKeyNotFoundError:
            return
        else:
            yield from glob_ext(key_collection, pattern)
