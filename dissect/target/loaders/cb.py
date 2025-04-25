from __future__ import annotations

import ipaddress
from functools import cached_property
from typing import TYPE_CHECKING

try:
    from cbc_sdk.errors import CredentialError
    from cbc_sdk.platform import Device
    from cbc_sdk.rest_api import CBCloudAPI
except ImportError:
    raise ImportError("Please install 'carbon-black-cloud-sdk-python' to use the 'cb://' target.")

from dissect.util import ts

from dissect.target.exceptions import (
    LoaderError,
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.filesystems.cb import CbFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import (
    RegistryHive,
    RegistryKey,
    RegistryValue,
    ValueType,
)
from dissect.target.loader import Loader
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path
    from urllib.parse import ParseResult

    from cbc_sdk.live_response_api import LiveResponseSession

    from dissect.target.target import Target


class CbLoader(Loader):
    """Use Carbon Black endpoints as targets using Live Response.

    Use as ``cb://<hostname or IP>[@<instance>]``.

    Refer to the Carbon Black documentation for setting up a ``credentials.cbc`` file.
    """

    def __init__(self, path: Path, parsed_path: ParseResult | None = None):
        super().__init__(path, parsed_path, resolve=False)

        self.host, _, instance = self.parsed_path.netloc.partition("@")

        try:
            self.cbc_api = CBCloudAPI(profile=instance or None)
        except CredentialError:
            raise LoaderError("The Carbon Black Cloud API key was not found or has the wrong permissions set")

        self.sensor = self.get_device()
        if not self.sensor:
            raise LoaderError("The device was not found within the specified instance")

        self.session = self.sensor.lr_session()

    def get_device(self) -> Device | None:
        try:
            ipaddress.ip_address(self.host)
            host_is_ip = True
        except ValueError:
            host_is_ip = False

        for cbc_sensor in self.cbc_api.select(Device).all():
            if host_is_ip:
                if cbc_sensor.last_internal_ip_address == self.host:
                    return cbc_sensor
            else:
                if device_name := getattr(cbc_sensor, "name", None):
                    device_name = device_name.lower()

                    # Sometimes the domain name is included in the device name
                    # E.g. DOMAIN\\Hostname
                    if "\\" in device_name:
                        device_name = device_name.split("\\")[1]

                    if device_name == self.host.lower():
                        return cbc_sensor

        return None

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        for drive in self.session.session_data["drives"]:
            cbfs = CbFilesystem(self.session, drive)

            target.filesystems.add(cbfs)
            target.fs.mount(drive.lower(), cbfs)

        target.add_plugin(CbRegistry(target, self.session), check_compatible=False)


class CbRegistry(RegistryPlugin):
    __register__ = False

    def __init__(self, target: Target, session: LiveResponseSession):
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
            except RegistryError:  # noqa: PERF203
                continue


class CbRegistryHive(RegistryHive):
    def __init__(self, session: LiveResponseSession, root_key: str):
        self.session = session
        self.root_key = root_key

    def key(self, key: str) -> CbRegistryKey:
        path = f"{self.root_key}\\{key}" if key else self.root_key
        return CbRegistryKey(self, path)


class CbRegistryKey(RegistryKey):
    def __init__(self, hive: CbRegistryHive, path: str):
        self.session = hive.session
        self._path: str = path
        self._name: str = path.rsplit("\\", 1)[-1]
        super().__init__(hive)

    @cached_property
    def data(self) -> dict:
        try:
            return self.session.list_registry_keys_and_values(self._path)
        except Exception:
            raise RegistryKeyNotFoundError(self.path)

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
        # To improve peformance, immediately return a "hollow" key object
        # Only listing all subkeys or reading a value will result in data being loaded
        # Technically this means we won't raise a RegistryKeyNotFoundError in the correct place
        return CbRegistryKey(self.hive, f"{self._path}\\{subkey}")

    def subkeys(self) -> list[CbRegistryKey]:
        return list(map(self.subkey, self.data["sub_keys"]))

    def _value(self, value: str) -> CbRegistryValue:
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
    def __init__(self, hive: CbRegistryHive, name: str, data: str, type: str):
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
    def value(self) -> ValueType:
        return self._value

    @property
    def type(self) -> str:
        return self._type
