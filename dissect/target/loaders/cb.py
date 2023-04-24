from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from cbc_sdk.errors import CredentialError
from cbc_sdk.platform import Device
from cbc_sdk.rest_api import CBCloudAPI

from dissect.target.exceptions import (
    CBCCredentialError,
    CBCDeviceError,
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.filesystems.cb import CbFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import RegistryHive, RegistryKey, RegistryValue
from dissect.target.helpers.utils import parse_path_uri
from dissect.target.loader import Loader
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from pathlib import Path

    from cbc_sdk.live_response_api import LiveResponseSession

    from dissect.target.target import Target


class CbLoader(Loader):
    def __init__(self, path: str, **kwargs):
        self.host, instance = kwargs["parsed_path"].netloc.split("@")
        super(CbLoader, self).__init__(path)

        # A profile will need to be given as argument to CBCloudAPI
        # e.g. cb://workstation@instance
        try:
            self.cbc_api = CBCloudAPI(profile=instance)
        except CredentialError:
            raise CBCCredentialError

        self.sensor = self.get_device()
        if not self.sensor:
            raise CBCDeviceError

        self.session = self.sensor.lr_session()

    def get_device(self) -> Device:
        for cbc_sensor in self.cbc_api.select(Device).all():
            if all([part.isdigit() for part in self.host.split(".")]):
                if cbc_sensor.last_internal_ip_address == self.host:
                    device_id = cbc_sensor.id
                    break
            else:
                try:
                    device_name = cbc_sensor.name.lower()
                except AttributeError:
                    continue

                if "\\" in device_name:
                    device_name = device_name.split("\\")[1]

                if device_name == self.host.lower():
                    device_id = cbc_sensor.id
                    break
        else:
            return None

        return self.cbc_api.select(Device, device_id)

    @staticmethod
    def detect(path: Path) -> bool:
        path_part, _, _ = parse_path_uri(path)
        return path_part == "cb"

    @staticmethod
    def find_all(path: Path) -> str:
        # TODO: Hostname wildcards
        yield path

    def map(self, target: Target) -> None:
        for drive in self.session.session_data["drives"]:
            cbfs = CbFilesystem(self.cbc_api, self.sensor, self.session, drive)
            target.filesystems.add(cbfs)
            target.fs.mount(drive.lower(), cbfs)


class CbRegistry(RegistryPlugin):
    def __init__(self, target: Target, session: LiveResponseSession):
        self.session = session
        super(CbRegistry, self).__init__(target)

    def _init_registry(self) -> None:
        for hive_name, rootkey in self.MAPPINGS.items():
            try:
                hive = CbRegistryHive(self.session, rootkey)
                self._add_hive(hive_name, hive, TargetPath(self.target.fs, "CBR"))
                self._map_hive(rootkey, hive)
            except RegistryError:
                continue


class CbRegistryHive(RegistryHive):
    def __init__(self, session: LiveResponseSession, rootkey: str):
        self.session = session
        self.rootkey = rootkey

    def key(self, key: str) -> CbRegistryKey:
        key = "\\".join([self.rootkey, key])
        return CbRegistryKey(self, key)


class CbRegistryKey(RegistryKey):
    def __init__(self, hive: str, key: str, data=None):
        super().__init__(hive)
        self.key = key
        self._data = data

    @property
    def data(self) -> dict:
        if not self._data:
            self._data = self.hive.session.list_registry_keys_and_values(self.key)
        return self._data

    @property
    def name(self) -> str:
        return self.key.split("\\")[-1]

    @property
    def path(self) -> str:
        return self.key

    @property
    def timestamp(self) -> None:
        return None

    def subkey(self, subkey: str) -> CbRegistryKey:
        subkey_val = subkey.lower()

        for val in self.data["sub_keys"]:
            if val.lower() == subkey_val:
                return CbRegistryKey(self.hive, "\\".join([self.key, subkey]), None)
        else:
            raise RegistryKeyNotFoundError(subkey)

    def subkeys(self) -> map:
        return map(self.subkey, self.data["sub_keys"])

    def value(self, value: str) -> str:
        reg_value = value.lower()
        for val in self.values():
            if val.name.lower() == reg_value:
                return val
        else:
            raise RegistryValueNotFoundError(value)

    def values(self) -> Iterable[CbRegistryValue]:
        return (
            CbRegistryValue(self.hive, val["registry_name"], val["registry_data"], val["registry_type"])
            for val in self.data["values"]
        )


class CbRegistryValue(RegistryValue):
    def __init__(self, hive: str, name: str, data: str, type_: str):
        super().__init__(hive)
        self._name = name
        self._type = type_

        if self._type == "pbREG_BINARY":
            self._value = bytes.fromhex(data)
        elif self._type in ("pbREG_DWORD", "pbREG_QWORD"):
            self._value = int(data)
        elif self._type == "pbREG_MULTI_SZ":
            self._value = data.split(",")
        else:
            self._value = data

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> str:
        return self._value

    @property
    def type(self) -> str:
        return self._type
