from __future__ import annotations

import re
from collections import OrderedDict
from configparser import ConfigParser
from functools import partial
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

WireGuardInterfaceRecord = TargetRecordDescriptor(
    "application/vpn/wireguard/interface",
    [
        ("string", "name"),  # basename of .conf file if unset
        ("net.ipaddress", "address"),
        ("string", "private_key"),
        ("varint", "listen_port"),
        ("string", "fw_mark"),
        ("string", "dns"),
        ("varint", "table"),
        ("varint", "mtu"),
        ("string", "preup"),
        ("string", "postup"),
        ("string", "predown"),
        ("string", "postdown"),
        ("path", "source"),
    ],
)

WireGuardPeerRecord = TargetRecordDescriptor(
    "application/vpn/wireguard/peer",
    [
        ("string", "name"),
        ("string", "public_key"),
        ("string", "pre_shared_key"),
        ("net.ipnetwork[]", "allowed_ips"),
        ("string", "endpoint"),
        ("varint", "persistent_keep_alive"),
        ("path", "source"),
    ],
)


class WireGuardPlugin(Plugin):
    """WireGuard configuration parser.

    References:
        - https://manpages.debian.org/testing/wireguard-tools/wg.8.en.html#CONFIGURATION_FILE_FORMAT
        - https://github.com/pirate/wireguard-docs
    """

    __namespace__ = "wireguard"

    # TODO: NetworkManager uses a different stanza format
    #       "/etc/NetworkManager/system-connections/Wireguard*",
    # TODO: systemd uses a different stanza format
    #       "/etc/systemd/network/wg*.netdev",
    #       "/etc/systemd/network/*wg*.netdev",
    # TODO: other locations such as $HOME/.config/wireguard
    # TODO: parse native network manager formats from MacOS, Ubuntu and Windows.

    CONFIG_GLOBS = (
        # Linux
        "/etc/wireguard/*.conf",
        # MacOS
        "/usr/local/etc/wireguard/*.conf",
        "/opt/homebrew/etc/wireguard/*.conf",
        # Windows
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\WireGuard\\Configurations\\*.dpapi",
        "C:\\Program Files\\WireGuard\\Data\\Configurations\\*.dpapi",
    )

    TUNNEL_NAME_RE = re.compile(r"\.(conf(\.dpapi)?|netdev)$")

    def __init__(self, target: Target):
        super().__init__(target)
        self.configs: list[Path] = []
        for path in self.CONFIG_GLOBS:
            self.configs.extend(self.target.fs.path("/").glob(path.lstrip("/")))

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No Wireguard configuration files found")

    @export(record=[WireGuardInterfaceRecord, WireGuardPeerRecord])
    def config(self) -> Iterator[WireGuardInterfaceRecord | WireGuardPeerRecord]:
        """Parses interface config files from wireguard installations."""

        for config_path in self.configs:
            if self.target.os == OperatingSystem.WINDOWS and config_path.suffix == ".dpapi":
                try:
                    config_buf = self.target.dpapi.decrypt_system_blob(config_path.read_bytes())
                    config_buf = config_buf.decode()
                except ValueError:
                    self.target.log.warning("Failed to decrypt WireGuard configuration at %s", config_path)
                    continue
            else:
                config_buf = config_path.read_text()

            config = _parse_config(config_buf)

            # Set up an iterator to go through all the sections and pre-set the fallback
            config_iterator = ((section, partial(config.get, section, fallback=None)) for section in config.sections())

            for section, config_dict in config_iterator:
                if "Interface" in section:
                    if address := config_dict("Address"):
                        address = address.split("/")[0]

                    yield WireGuardInterfaceRecord(
                        name=config_path.stem,
                        address=address,
                        listen_port=config_dict("ListenPort"),
                        private_key=config_dict("PrivateKey"),
                        fw_mark=config_dict("FwMark"),
                        dns=config_dict("DNS"),
                        table=config_dict("Table"),
                        mtu=config_dict("MTU"),
                        preup=config_dict("PreUp"),
                        postup=config_dict("PostUp"),
                        predown=config_dict("PreDown"),
                        postdown=config_dict("PostDown"),
                        source=config_path,
                        _target=self.target,
                    )

                if "Peer" in section:
                    if allowed_ips := config_dict("AllowedIPs"):
                        allowed_ips = [value.strip() for value in allowed_ips.split(",")]

                    yield WireGuardPeerRecord(
                        name=config_dict("Name"),
                        public_key=config_dict("PublicKey"),
                        pre_shared_key=config_dict("PreSharedKey"),
                        allowed_ips=allowed_ips,
                        endpoint=config_dict("Endpoint"),
                        persistent_keep_alive=config_dict("PersistentKeepAlive"),
                        source=config_path,
                        _target=self.target,
                    )


def _parse_config(content: str) -> ConfigParser:
    """Parses WireGuard config ini stanza files using Python's ConfigParser module.

    We create our own MultiDict definition from an ordered dict, since we want
    to allow multiple 'Peer' sections. We prepend section names with numbers;
    'Interface', 'Peer1', 'Peer2', 'Peer2', etc.
    This way we prevent duplicate section keys.
    """

    cp = ConfigParser(defaults=None, dict_type=MultiDict, strict=False)
    # Set to use str so it doesn't do any lower operation on the keys.
    cp.optionxform = str
    cp.read_string(content)
    return cp


class MultiDict(OrderedDict):
    """OrderedDict implementation which allows multiple values for the keys ``Peer`` and ``Interface``."""

    def __init__(self, *args, **kwargs):
        self._unique = 0
        super().__init__(*args, **kwargs)

    def __setitem__(self, key: str, val: str):
        if isinstance(val, dict) and (key in ["Peer", "Interface"]):
            self._unique += 1
            key += str(self._unique)
        super().__setitem__(key, val)
