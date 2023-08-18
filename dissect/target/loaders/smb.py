from __future__ import annotations

import os
import time
from datetime import datetime
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Union
from urllib.parse import ParseResult, parse_qsl

from dissect.regf import regf
from dissect.util import ts
from impacket.dcerpc.v5 import rpcrt, rrp, scmr, transport
from impacket.smbconnection import SessionError, SMBConnection

from dissect.target import Target
from dissect.target.exceptions import (
    LoaderError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.filesystems.smb import SmbFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import RegistryHive, RegistryKey, RegistryValue
from dissect.target.loader import Loader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from impacket.dcerpc.v5.srvs import SHARE_INFO_1


class SmbLoader(Loader):
    """Use remote SMB servers as targets.

    This loader maps SMB shares from a remote SMB server as filesystems. It makes
    use of Impacket's ``SMBConnection`` class to connect to the remote server and
    enumerate all available shares. The shares are then mapped as filesystems
    in the target. You can use the following examples to connect to a guest.

    Connect as guest (you're probably not going to get very far with this one)::

        smb://10.10.128.3

    Connect as administrator using NTLM password authentication::

        smb://administrator:Dissect123!@10.10.128.3

    Connect as administrator using NTLM pass-the-hash authentication::

        smb://administrator@10.10.128.3?hash=3c19c73ccd2bbcb84c592321caa4b1be

    Connect using a Kerberos authentication::

        smb://administrator@infected.dissect.lab?kerberos=true&ip=10.10.128.3&ticket=administrator.ccache&dc=dc01.dissect.lab&dc-ip=10.10.10.10

    You can also use the following environment variables instead:

    - ``SMB_TARGET_IP``
    - ``SMB_TARGET_HOST``
    - ``SMB_DOMAIN``
    - ``SMB_USERNAME``
    - ``SMB_PASSWORD``
    - ``SMB_KERBEROS_TICKET (or KRB5CCNAME)``
    - ``SMB_KERBEROS_DC``
    - ``SMB_KERBEROS_DC_IP``
    - ``SMB_KERBEROS_AES_KEY``

    When using environment variables, you can invoke this loader using an empty ``smb://`` URI.
    """

    MACHINE_NAME = "DISSECT-TARGET"
    EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
    EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        self._uri: ParseResult = kwargs.get("parsed_path")
        if self._uri is None:
            raise LoaderError("Missing URI connection details")

        self._params = dict(parse_qsl(self._uri.query, keep_blank_values=False))

        self._ip = self._params.get("ip", os.getenv("SMB_TARGET_IP", self._uri.hostname))
        self._host = self._params.get("host", os.getenv("SMB_TARGET_HOST", self._uri.hostname))
        self._domain = self._params.get("domain", os.getenv("SMB_DOMAIN", "."))
        self._username = self._uri.username or os.getenv("SMB_USERNAME", "Guest")
        self._password = self._uri.password or os.getenv("SMB_PASSWORD", "")
        self._nt, self._lm = "", ""
        if not self._password:
            self._nt, self._lm = self._get_hashes()

        krb_ticket_params = self._params.get("ticket", self._params.get("ccache", ""))
        krb_ticket_env = os.getenv("SMB_KERBEROS_TICKET", os.getenv("KRB5CCNAME", ""))
        self._krb_ticket = krb_ticket_params or krb_ticket_env
        self._krb_aes = self._params.get("aes", os.getenv("SMB_KERBEROS_AES_KEY", ""))
        self._krb_dc = self._params.get("dc", os.getenv("SMB_KERBEROS_DC", ""))
        self._krb_dc_ip = self._params.get("dc-ip", os.getenv("SMB_KERBEROS_DC_IP", ""))
        self._use_kerberos = self._params.get("kerberos", "").lower() in ("true", "1", "yes")

        self._name = f"smb://{self._domain}/{self._username}@{self._host}"

        self._conn = SMBConnection(
            remoteName=self._host,
            remoteHost=self._ip,
            myName=self.MACHINE_NAME,
        )

        if self._use_kerberos:
            # Hack to make Impacket load our kerberos ticket
            os.environ["KRB5CCNAME"] = self._krb_ticket

            # Perform kerberos login
            self._conn.kerberosLogin(
                domain=self._domain,
                user=self._username,
                password=self._password,
                nthash=self._nt,
                lmhash=self._lm,
                aesKey=self._krb_aes,
                kdcHost=self._krb_dc_ip,
                useCache=bool(self._krb_ticket),
            )
        else:
            self._conn.login(
                domain=self._domain,
                user=self._username,
                password=self._password,
                nthash=self._nt,
                lmhash=self._lm,
            )

    def _get_hashes(self) -> tuple[str, str]:
        """Attempt to parse NT and LM hashes from the URI query string."""
        nt = self._params.get("nt", self.EMPTY_NT)
        lm = self._params.get("lm", self.EMPTY_LM)

        hashes = self._params.get("hash", self._params.get("hashes", f"{nt}:{lm}"))

        if ":" in hashes:
            nt, lm = hashes.split(":", 1)
        else:
            nt = hashes

        return nt, lm

    @staticmethod
    def detect(path: Path) -> bool:
        """This loader can only be activated with the URI-scheme ``smb://<ip>``."""
        return False

    def map(self, target: Target) -> None:
        """Map all target filesystems (network shares) from the SMB connection."""
        target.log.debug("Attempting to list shares...")
        shares: list[SHARE_INFO_1] = self._conn.listShares()
        for share in shares:
            share_name: str = share["shi1_netname"][:-1]
            try:
                smb_filesystem = SmbFilesystem(self._conn, share_name)
                target.filesystems.add(smb_filesystem)

                mount_name = share_name
                if len(share_name) == 2:
                    mount_name = share_name.lower().replace("$", ":")

                target.fs.mount(mount_name, smb_filesystem)

            except SessionError as e:
                target.log.warning("Failed to mount share '%s', reason: %s", share_name, e)

        target.add_plugin(SmbRegistry(target, self._conn), check_compatible=False)
        target._os_plugin = WindowsPlugin


class SmbRegistry(RegistryPlugin):
    __register__ = False

    def __init__(self, target: Target, conn: SMBConnection):
        self.conn = conn
        self._svc_handle = None
        self._was_stopped = False
        self._was_disabled = False
        self._svcctl = None
        self._winreg = None
        super().__init__(target)

    def check_compatible(self) -> bool:
        return False

    def _init_registry(self) -> None:
        self._svcctl = _connect_rpc(self.conn, "ncacn_np:445[\\pipe\\svcctl]", scmr.MSRPC_UUID_SCMR)
        self._check_service_status()

        self._winreg = _connect_rpc(self.conn, "ncacn_np:445[\\pipe\\winreg]", rrp.MSRPC_UUID_RRP)

        hklm_hive = SmbRegistryHive(self._winreg, "HKEY_LOCAL_MACHINE", rrp.hOpenLocalMachine(self._winreg)["phKey"])
        hku_hive = SmbRegistryHive(self._winreg, "HKEY_USERS", rrp.hOpenUsers(self._winreg)["phKey"])

        self._add_hive("HKLM", hklm_hive, TargetPath(self.target.fs, "HKLM"))
        self._add_hive("HKU", hku_hive, TargetPath(self.target.fs, "HKU"))
        self._map_hive("HKEY_LOCAL_MACHINE", hklm_hive)
        self._map_hive("HKEY_USERS", hku_hive)

    def _init_users(self) -> None:
        pass

    def __del__(self) -> None:
        if hasattr(self, "_was_stopped") and self._was_stopped:
            scmr.hRControlService(self._svcctl, self._svc_handle, scmr.SERVICE_CONTROL_STOP)

        if hasattr(self, "_was_disabled") and self._was_disabled:
            scmr.hRChangeServiceConfigW(self._svcctl, self._svc_handle, dwStartType=0x4)

        if hasattr(self, "_svcctl"):
            self._svcctl.disconnect()

        if hasattr(self, "_winreg"):
            self._winreg.disconnect()

    def _check_service_status(self) -> None:
        manager_handle = scmr.hROpenSCManagerW(self._svcctl)["lpScHandle"]
        self._svc_handle = scmr.hROpenServiceW(self._svcctl, manager_handle, "RemoteRegistry")["lpServiceHandle"]

        current_state = scmr.hRQueryServiceStatus(self._svcctl, self._svc_handle)["lpServiceStatus"]["dwCurrentState"]
        if current_state == scmr.SERVICE_STOPPED:
            self._was_stopped = True

            start_type = scmr.hRQueryServiceConfigW(self._svcctl, self._svc_handle)["lpServiceConfig"]["dwStartType"]
            if start_type == 0x4:
                self._was_disabled = True
                scmr.hRChangeServiceConfigW(self._svcctl, self._svc_handle, dwStartType=0x3)

            scmr.hRStartServiceW(self._svcctl, self._svc_handle)
            time.sleep(1)


class SmbRegistryHive(RegistryHive):
    def __init__(self, winreg: rpcrt.DCERPC_v5, name: str, handle: int):
        self.winreg = winreg
        self.name = name
        self.handle = handle

    def key(self, key: str) -> SmbRegistryKey:
        return SmbRegistryKey(self, key)


class SmbRegistryKey(RegistryKey):
    hive: SmbRegistryHive

    def __init__(self, hive: SmbRegistryHive, path: str):
        self._path = path
        self._name: str = path.rsplit("\\", 1)[-1]
        super().__init__(hive)

    @cached_property
    def handle(self) -> int:
        try:
            return rrp.hBaseRegOpenKey(
                self.hive.winreg,
                self.hive.handle,
                self._path,
                samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE,
            )["phkResult"]
        except rrp.DCERPCSessionError:
            raise RegistryKeyNotFoundError(self.path)

    @property
    def name(self) -> str:
        return self._name

    @property
    def path(self) -> str:
        return "\\".join([self.hive.name, self._path]) if self._path else self.hive.name

    @property
    def timestamp(self) -> datetime:
        return ts.from_unix(0)

    def subkey(self, subkey: str) -> SmbRegistryKey:
        # To improve peformance, immediately return a "hollow" key object
        # Only listing all subkeys or reading a value will result in data being loaded
        # Technically this means we won't raise a RegistryKeyNotFoundError in the correct place
        return SmbRegistryKey(self.hive, "\\".join([self._path, subkey]) if self._path else subkey)

    def subkeys(self) -> list[SmbRegistryKey]:
        subkeys = []
        handle = self.handle

        i = 0
        while True:
            try:
                name = rrp.hBaseRegEnumKey(self.hive.winreg, handle, i)["lpNameOut"][:-1]
                subkeys.append(self.subkey(name))
                i += 1
            except Exception:
                break

        return subkeys

    def value(self, value: str) -> str:
        reg_value = value.lower()
        for val in self.values():
            if val.name.lower() == reg_value:
                return val
        else:
            raise RegistryValueNotFoundError(value)

    def values(self) -> list[SmbRegistryValue]:
        values = []
        handle = self.handle

        i = 0
        while True:
            try:
                result = rrp.hBaseRegEnumValue(self.hive.winreg, handle, i)
                values.append(
                    SmbRegistryValue(
                        self.hive,
                        result["lpValueNameOut"][:-1] or "(Default)",
                        b"".join(result["lpData"]),
                        result["lpType"],
                    )
                )
                i += 1
            except Exception:
                break

        return values


class SmbRegistryValue(RegistryValue):
    def __init__(self, hive: str, name: str, data: bytes, type: int):
        super().__init__(hive)
        self._name = name
        self._type = type
        self._value = regf.parse_value(type, data)

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> str:
        return self._value

    @property
    def type(self) -> str:
        return self._type


def _connect_rpc(conn: SMBConnection, binding: str, uuid: bytes):
    rpc = transport.DCERPCTransportFactory(binding)
    rpc.set_smb_connection(conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce
