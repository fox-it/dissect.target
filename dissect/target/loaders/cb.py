from urllib.parse import urlparse

from cbapi.live_response_api import LiveResponseError
from cbapi.response import CbResponseAPI, Sensor

from dissect.target.exceptions import (
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.filesystems.cb import CbFilesystem
from dissect.target.helpers.regutil import RegistryHive, RegistryKey, RegistryValue
from dissect.target.loader import Loader
from dissect.target.plugins.os.windows.registry import RegistryPlugin


class CbLoader(Loader):
    def __init__(self, path, **kwargs):
        path = str(path)
        super().__init__(path)
        self.uri = urlparse(path)
        self.host = self.uri.netloc

        self.cb = CbResponseAPI()
        if self.host.isdigit():
            self.sensor = self.cb.select(Sensor, self.host)
        else:
            q = self.cb.select(Sensor)

            if all([part.isdigit() for part in self.host.split(".")]):
                q = q.where(f"ip:{self.host}")
            else:
                q = q.where(f"hostname:{self.host}")

            res = list(q)
            if len(res) > 1:
                res = sorted(res, key=lambda s: s.last_checkin_time, reverse=True)

            self.sensor = res[0]

        self.session = self.sensor.lr_session()

    @staticmethod
    def detect(path):
        return urlparse(str(path)).scheme == "cb"

    def map(self, target):
        for drive in self.session.session_data["drives"]:
            cbfs = CbFilesystem(self.cb, self.sensor, self.session, drive)
            target.filesystems.add(cbfs)
            target.fs.mount(drive.lower(), cbfs)
        target.add_plugin(CbRegistry(target, self.session))


class CbRegistry(RegistryPlugin):
    def __init__(self, target, session):
        self.session = session
        super().__init__(target)

    def _init_registry(self):
        hive = CbRegistryHive(self.session)
        self.add_hive("", hive)
        self.map_hive("", hive)


class CbRegistryHive(RegistryHive):
    def __init__(self, session):
        self.session = session

    def key(self, key):
        key = key.replace("/", "\\")
        try:
            data = self.session.list_registry_keys_and_values(key)
            return CbRegistryKey(self.session, key, data)
        except LiveResponseError:
            raise RegistryKeyNotFoundError(key)


class CbRegistryKey(RegistryKey):
    def __init__(self, session, key, data):
        self.session = session
        self.key = key
        self._data = data

    @property
    def data(self):
        if not self._data:
            self._data = self.session.list_registry_keys_and_values(self.key)
        return self._data

    @property
    def name(self):
        return self.key.split("\\")[-1]

    @property
    def path(self):
        return self.key

    @property
    def timestamp(self):
        return None

    def subkey(self, subkey):
        if subkey not in self.data["sub_keys"]:
            raise RegistryKeyNotFoundError(subkey)

        return CbRegistryKey(self.session, "\\".join([self.key, subkey]), None)

    def subkeys(self):
        return map(self.subkey, self.data["sub_keys"])

    def value(self, value):
        val = value.lower()
        for v in self.values():
            if v.name.lower() == val:
                return v
        else:
            raise RegistryValueNotFoundError(value)

    def values(self):
        return (CbRegistryValue(v["value_name"], v["value_data"], v["value_type"]) for v in self.data["values"])


class CbRegistryValue(RegistryValue):
    def __init__(self, name, data, type_):
        self._name = name
        self._type = type_

        if self._type in ("REG_SZ", "REG_EXPAND_SZ"):
            self._value = data[0]
        else:
            self._value = data

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        return self._value

    @property
    def type(self):
        return self._type
