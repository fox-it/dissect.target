from __future__ import annotations

from datetime import datetime
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import ParseResult

from cbc_sdk.errors import CredentialError
from cbc_sdk.live_response_api import LiveResponseSession
from cbc_sdk.platform import Device
from cbc_sdk.rest_api import CBCloudAPI
from dissect.util import ts

from dissect.target.exceptions import (
    LoaderError,
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
    def __init__(self, path: str, parsed_path: ParseResult = None, **kwargs):
        self.host, _, instance = parsed_path.netloc.partition("@")
        super(CbLoader, self).__init__(path)

        # A profile will need to be given as argument to CBCloudAPI
        # e.g. cb://workstation@instance
        try:
            self.cbc_api = CBCloudAPI(profile=instance)
        except CredentialError:
            raise LoaderError("The Carbon Black Cloud API key was not found or has the wrong set of permissions set")

        self.sensor = self.get_device()
        if not self.sensor:
            raise LoaderError("The device was not found within the specified instance")

        self.session = self.sensor.lr_session()

    def get_device(self) -> Optional[Device]:
        host_is_ip = self.host.count(".") == 3 and all([part.isdigit() for part in self.host.split(".")])

        for cbc_sensor in self.cbc_api.select(Device).all():
            if host_is_ip:
                if cbc_sensor.last_internal_ip_address == self.host:
                    return cbc_sensor
            else:
                try:
                    device_name = cbc_sensor.name.lower()
                except AttributeError:
                    continue

                # Sometimes the domain name is included in the device name
                # E.g. DOMAIN\\Hostname
                if "\\" in device_name:
                    device_name = device_name.split("\\")[1]

                if device_name == self.host.lower():
                    return cbc_sensor

        return None

    @staticmethod
    def detect(path: Path) -> bool:
        path_part, _, _ = parse_path_uri(path)
        return path_part == "cb"

    def map(self, target: Target) -> None:
        for drive in self.session.session_data["drives"]:
            cbfs = CbFilesystem(self.session, drive)

            target.filesystems.add(cbfs)
            target.fs.mount(drive.lower(), cbfs)

        target.add_plugin(CbRegistry(target, self.session), check_compatible=False)


class CbRegistry(RegistryPlugin):
    __findable__ = False

    def __init__(self, target: Target, session: LiveResponseSession = None):
        self.session = session
        super().__init__(target)

    def check_compatible(self) -> bool:
        return False

    def _init_registry(self) -> None:
        for hive_name, root_key in self.MAPPINGS.items():
            try:
                hive = CbRegistryHive(self.session, root_key)
                self._add_hive(hive_name, hive, TargetPath(self.target.fs, "CBR"))
                self._map_hive(root_key, hive)
            except RegistryError:
                continue


class CbRegistryHive(RegistryHive):
    def __init__(self, session: LiveResponseSession, root_key: str):
        self.session = session
        self.root_key = root_key

    def key(self, key: str) -> CbRegistryKey:
        path = "\\".join([self.root_key, key]) if key else self.root_key
        return CbRegistryKey(self, path)


class CbRegistryKey(RegistryKey):
    def __init__(self, hive: str, path: str):
        self._path: str = path
        self._name: str = path.split("\\")[-1]
        super().__init__(hive)

    @cached_property
    def data(self) -> dict:
        return self.hive.session.list_registry_keys_and_values(self._path)

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return self._path

    @property
    def timestamp(self) -> datetime:
        return ts.from_unix(0)

    def subkey(self, subkey: str) -> CbRegistryKey:
        subkey_val = subkey.lower()

        for val in self.data["sub_keys"]:
            if val.lower() == subkey_val:
                return CbRegistryKey(self.hive, "\\".join([self._path, subkey]))
        else:
            raise RegistryKeyNotFoundError(subkey)

    def subkeys(self) -> list[CbRegistryKey]:
        return list(map(self.subkey, self.data["sub_keys"]))

    def value(self, value: str) -> str:
        reg_value = value.lower()
        for val in self.values():
            if val.name.lower() == reg_value:
                return val
        else:
            raise RegistryValueNotFoundError(value)

    def values(self) -> list[CbRegistryValue]:
        return [
            CbRegistryValue(self.hive, val["registry_name"], val["registry_data"], val["registry_type"])
            for val in self.data["values"]
        ]


class CbRegistryValue(RegistryValue):
    def __init__(self, hive: str, name: str, data: str, type: str):
        super().__init__(hive)
        self._name = name
        self._type = type

        if self._type == "pbREG_BINARY":
            self._value = bytes.fromhex(data)
        elif self._type in ("pbREG_DWORD", "pbREG_QWORD", "pbREG_DWORD_BIG_ENDIAN"):
            self._value = int(data)
        elif self._type == "pbREG_MULTI_SZ":
            self._value = data.split(",")
        else:
            # pbREG_NONE, pbREG_SZ, pbREG_EXPAND_SZ
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
