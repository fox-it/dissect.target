import re
import warnings
from collections import defaultdict
from functools import lru_cache

from dissect.target.exceptions import HiveUnavailableError, RegistryKeyNotFoundError
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.helpers.regutil import (
    HiveCollection,
    KeyCollection,
    RegfHive,
    RegistryKey,
    VirtualHive,
)
from dissect.target.plugin import Plugin, internal
from dissect.target.plugins.general.users import UserDetails

controlset_regex = re.compile("CurrentControlSet", flags=re.IGNORECASE)


class RegistryPlugin(Plugin):
    """Provides registry access for Windows targets.

    Acts much the same to how the registry works on a live Windows machine.
    Hives are correctly mapped under e.g. HKLM\\SOFTWARE.

    Internal functions only.
    """

    __namespace__ = "registry"

    SHORTNAMES = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKCC": "HKEY_CURRENT_CONFIG",
        "HKCU": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
    }

    MAPPINGS = {
        "SAM": "HKEY_LOCAL_MACHINE\\SAM",
        "SECURITY": "HKEY_LOCAL_MACHINE\\SECURITY",
        "SOFTWARE": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "SYSTEM": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "COMPONENTS": "HKEY_LOCAL_MACHINE\\COMPONENTS",
        "DEFAULT": "HKEY_USERS\\.DEFAULT",
        "BCD": "HKEY_LOCAL_MACHINE\\BCD00000000",
        "ELAM": "HKEY_LOCAL_MACHINE\\ELAM",
    }

    SYSTEM = [
        "SAM",
        "SECURITY",
        "SOFTWARE",
        "SYSTEM",
        "COMPONENTS",
        "DEFAULT",
        "ELAM",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._root = VirtualHive()
        self._hive_collections = defaultdict(HiveCollection)
        self._hive_paths = []

        self._hives_to_users: dict[RegfHive, UserDetails] = dict()

        self._controlsets = []
        self._currentcontrolset = None
        self._users_loaded = False
        self._init_registry()

    def _init_registry(self):
        dirs = ["sysvol/windows/system32/config", "sysvol/windows/system32/config/RegBack"]

        for d in dirs:
            config_dir = self.target.fs.path(d)
            for fname in self.SYSTEM:
                hive_file = config_dir.joinpath(fname)
                if not hive_file.exists():
                    self.target.log.debug("Could not find hive: %s", hive_file)
                    continue

                if hive_file.stat().st_size == 0:
                    self.target.log.warning("Empty hive: %s", hive_file)
                    continue

                try:
                    hf = RegfHive(hive_file)
                    self.add_hive(fname, hf, hive_file)
                except Exception as e:
                    self.target.log.warning("Could not open hive: %s", hive_file, exc_info=e)
                    continue

        for drive in ["sysvol", "efi"]:
            bcd = self.target.fs.path(drive).joinpath("boot/BCD")
            if not bcd.exists():
                continue

            if bcd.stat().st_size == 0:
                self.target.log.warning("Empty BCD hive: %s", bcd)
                continue

            try:
                hf = RegfHive(bcd)
                self.add_hive("BCD", hf, bcd)
            except Exception as e:
                self.target.log.warning("Could not open BCD: %s", bcd, exc_info=e)

        for hive, location in self.MAPPINGS.items():
            if hive in self._hive_collections:
                self.map_hive(location, self._hive_collections[hive])

    def _init_users(self):
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
                    self.add_hive(user.sid, ntuserhive, ntuser)

                    self.map_hive(f"HKEY_USERS\\{user.sid}", ntuserhive)

                    self._hives_to_users[ntuserhive] = user_details
                except Exception as e:
                    self.target.log.warning("Could not open ntuser.dat: %s", ntuser, exc_info=e)

            usrclass = user_details.home_path.joinpath("AppData/Local/Microsoft/Windows/usrclass.dat")

            if not usrclass.exists():
                self.target.log.debug("Could not find usrclass.dat: %s", usrclass)
            elif usrclass.stat().st_size == 0:
                self.target.log.warning("Empty UsrClass.DAT hive: %s", usrclass)
            else:
                try:
                    usr_class_hive = RegfHive(usrclass)
                    self.add_hive(f"{user.sid}_Classes", usr_class_hive, usrclass)
                    self.map_hive(f"HKEY_USERS\\{user.sid}\\Software\\Classes", usr_class_hive)
                    self.map_hive(f"HKEY_USERS\\{user.sid}_Classes", usr_class_hive)

                    self._hives_to_users[usr_class_hive] = user_details
                except Exception as e:
                    self.target.log.warning("Could not open usrclass.dat: %s", usrclass, exc_info=e)

        self._users_loaded = True

    @internal
    def load_user_hives(self):
        self._init_users()

    @internal
    def add_hive(self, name, hive, path):
        self._hive_collections[name.upper()].add(hive)
        self._hive_paths.append((name, hive, path))

    @internal
    def map_hive(self, location, hive):
        self._root.map_hive(location, hive)

    def check_compatible(self):
        return len(self._hive_collections) > 0

    @property
    def controlsets(self):
        if not self._controlsets:
            for key in self.key("HKLM\\SYSTEM").subkeys():
                if key.name.startswith("ControlSet0"):
                    self._controlsets.append(key.name)
                if key.name == "Select":
                    current_value = key.value("Current").value
                    self._currentcontrolset = f"ControlSet{current_value:03d}"
        return self._controlsets

    @internal
    def root(self):
        """Returns the root of the virtual registry."""
        return self.key()

    @internal
    @lru_cache(4096)
    def key(self, key=None):
        """Query the virtual registry on the given key.

        Returns a KeyCollection which contains all keys that match
        the query.
        """
        if not key:
            return self._root.root()

        key = key.strip("\\")

        if controlset_regex.findall(key):
            if not self._currentcontrolset:
                self.target.log.warning("No known destination for CurrentControlSet link")
                raise RegistryKeyNotFoundError(key)

            key = controlset_regex.sub(self._currentcontrolset, key, 1)

        hive, _, path = key.partition("\\")
        for short_name, name in self.SHORTNAMES.items():
            if hive.upper() == short_name.upper():
                hive = name
                break

        key = "\\".join([hive, path])

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
        elif hive == "HKEY_CLASSES_ROOT":
            res = self.key(f"HKEY_CURRENT_USER\\Software\\Classes\\{path}")
            res.add(self.key(f"HKEY_LOCAL_MACHINE\\Software\\Classes\\{path}"))
            return res
        else:
            res = self._root.key(key)

        if not isinstance(res, KeyCollection):
            res = KeyCollection([res])

        return res

    @internal
    def value(self, key, value):
        """Convenience method for accessing a specific value."""
        return self.key(key).value(value)

    @internal
    def subkey(self, key, subkey):
        """Convenience method for accessing a specific subkey."""
        return self.key(key).subkey(subkey)

    @internal
    def iterkeys(self, keys):
        warnings.warn("The iterkeys() function is deprecated, use keys() instead", DeprecationWarning)
        for key in self.keys(keys):
            yield key

    @internal
    def keys(self, keys):
        """Yields all keys that match the given queries.

        Automatically resolves CurrentVersion keys. Also unrolls KeyCollections.
        """
        keys = [keys] if not isinstance(keys, list) else keys

        for key in self._iterkeypaths(keys):
            try:
                res = self.key(key)
                for r in res:
                    yield r
            except RegistryKeyNotFoundError:
                pass
            except HiveUnavailableError:
                pass

    def _iterkeypaths(self, keys):
        for key in keys:
            if not self.controlsets or not controlset_regex.search(key):
                yield key
                continue

            for controlset in self.controlsets:
                yield controlset_regex.sub(controlset, key)

    @internal
    def iterhives(self):
        """Returns an iterator for all hives.

        Items are tuples with three members: (name, hive, path)
        """
        return iter(self._hive_paths)

    @internal
    def mappings(self):
        """Return hive mappings."""
        return self.MAPPINGS

    @internal
    def get_user_details(self, key: RegistryKey) -> UserDetails:
        """Return user details for the user who owns a registry hive that contains the provided key"""
        if not key.hive or not key.hive.filepath:
            return

        return self._hives_to_users.get(key.hive)

    @internal
    def get_user(self, key: RegistryKey) -> WindowsUserRecord:
        """Return user record for the user who owns a registry hive that contains the provided key"""
        details = self._hives_to_users.get(key.hive)
        if details:
            return details.user
