import re
from collections import OrderedDict
from configparser import ConfigParser
from os.path import basename
from pathlib import Path
from typing import Iterator, Union

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export

WireGuardInterfaceRecord = TargetRecordDescriptor(
    "application/vpn/wireguard/interface",
    [
        ("string", "name"),  # basename of .conf file if unset
        ("net.ipaddress", "address"),
        ("string", "private_key"),
        ("string", "listen_port"),
        ("string", "fw_mark"),
        ("string", "dns"),
        ("varint", "table"),
        ("varint", "mtu"),
        ("string", "preup"),
        ("string", "postup"),
        ("string", "predown"),
        ("string", "postdown"),
        ("string", "source"),
    ],
)

WireGuardPeerRecord = TargetRecordDescriptor(
    "application/vpn/wireguard/peer",
    [
        ("string", "name"),
        ("string", "public_key"),
        ("string", "pre_shared_key"),
        ("net.ipnetwork", "allowed_ips"),
        ("string", "endpoint"),
        ("varint", "persistent_keep_alive"),
        ("string", "source"),
    ],
)


class WireGuardPlugin(Plugin):
    """WireGuard configuration parser.

    References:
        - https://manpages.debian.org/testing/wireguard-tools/wg.8.en.html#CONFIGURATION_FILE_FORMAT
        - https://github.com/pirate/wireguard-docs
    """

    __namespace__ = "wireguard"

    """
    TODO: NetworkManager uses a different stanza format
          "/etc/NetworkManager/system-connections/Wireguard*",
    TODO: systemd uses a different stanza format
          "/etc/systemd/network/wg*.netdev",
          "/etc/systemd/network/*wg*.netdev",
    TODO: other locations such as $HOME/.config/wireguard
    TODO: parse native network manager formats from MacOS, Ubuntu and Windows.
    """

    CONFIG_GLOBS = [
        # Linux
        "/etc/wireguard/*.conf",
        # MacOS
        "/usr/local/etc/wireguard/*.conf",
        "/opt/homebrew/etc/wireguard/*.conf",
        # Windows
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\WireGuard\\Configurations\\*.dpapi",
        "C:\\Program Files\\WireGuard\\Data\\Configurations\\*.dpapi",
    ]

    TUNNEL_NAME_RE = re.compile(r"\.(conf(\.dpapi)?|netdev)$")

    def __init__(self, target) -> None:
        super().__init__(target)
        self.configs: list[Path] = []
        for path in self.CONFIG_GLOBS:
            self.configs.extend(self.target.fs.path().glob(path.lstrip("/")))

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No Wireguard configuration files found")

    @export(record=[WireGuardInterfaceRecord, WireGuardPeerRecord])
    def config(self) -> Iterator[Union[WireGuardInterfaceRecord, WireGuardPeerRecord]]:
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

            for section in config.sections():
                if "Interface" in section:
                    if address := config.get(section, "Address", fallback=None):
                        address = address.split("/")[0]
                    name = basename(config_path)
                    name = self.TUNNEL_NAME_RE.sub("", name)
                    yield WireGuardInterfaceRecord(
                        name=name,
                        address=address,
                        listen_port=config.get(section, "ListenPort", fallback=None),
                        private_key=config.get(section, "PrivateKey", fallback=None),
                        fw_mark=config.get(section, "FwMark", fallback=None),
                        dns=config.get(section, "DNS", fallback=None),
                        table=config.get(section, "Table", fallback=None),
                        mtu=config.get(section, "MTU", fallback=None),
                        preup=config.get(section, "PreUp", fallback=None),
                        postup=config.get(section, "PostUp", fallback=None),
                        predown=config.get(section, "PreDown", fallback=None),
                        postdown=config.get(section, "PostDown", fallback=None),
                        source=config_path,
                        _target=self.target,
                    )

                if "Peer" in section:
                    yield WireGuardPeerRecord(
                        name=config.get(section, "Name", fallback=None),
                        public_key=config.get(section, "PublicKey", fallback=None),
                        pre_shared_key=config.get(section, "PreSharedKey", fallback=None),
                        allowed_ips=config.get(section, "AllowedIPs", fallback=None),
                        endpoint=config.get(section, "Endpoint", fallback=None),
                        persistent_keep_alive=config.get(section, "PersistentKeepAlive", fallback=None),
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
    cp.read_string(content)
    return cp


class MultiDict(OrderedDict):
    def __init__(self, *args, **kwargs):
        self._unique = 0
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, val):
        if isinstance(val, dict) and (key == "Peer" or key == "Interface"):
            self._unique += 1
            key += str(self._unique)
        super().__setitem__(key, val)
