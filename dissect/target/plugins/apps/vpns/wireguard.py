"""
    WireGuard configuration parser.

    Resources:
    - https://manpages.debian.org/testing/wireguard-tools/wg.8.en.html#CONFIGURATION_FILE_FORMAT
    - https://github.com/pirate/wireguard-docs
"""

from collections import OrderedDict
from typing import Iterator
from configparser import ConfigParser
from dissect.target.plugin import Plugin, export, internal
from dissect.target.helpers.record import TargetRecordDescriptor
from os.path import basename

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
    __namespace__ = "wireguard"

    """
    # TODO: NetworkManager uses a different stanza format
    # "/etc/NetworkManager/system-connections/Wireguard*",
    # TODO: systemd uses a different stanza format
    # "/etc/systemd/network/wg*.netdev",
    # "/etc/systemd/network/*wg*.netdev",
    # TODO: other locations such as $HOME/.config/wireguard
    # TODO: parse native network manager formats from MacOS, Ubuntu and Windows.
    """
    config_globs = [
        # Linux
        "/etc/wireguard/*.conf",
        # Windows
        "AppData/Local/WireGuard/Configurations/*.conf",
        # MacOS
        "/usr/local/etc/wireguard/*.conf",
        "/opt/homebrew/etc/wireguard/*.conf",
    ]

    def __init__(self, target) -> None:
        super().__init__(target)
        self.configs = []

    def check_compatible(self) -> bool:
        for path in self.config_globs:
            cfgs = list(self.target.fs.path().glob(path.lstrip("/")))
            if len(cfgs) > 0:
                for cfg in cfgs:
                    self.configs.append(cfg)
        if len(self.configs) > 0:
            return True

    @export(record=WireGuardInterfaceRecord or WireGuardPeerRecord)
    def config(self) -> Iterator[WireGuardInterfaceRecord or WireGuardPeerRecord]:
        """
        Parses interface config files from wireguard installations.
        """

        for config_path in self.configs:

            with self.target.fs.path(config_path).open("rt") as f:
                config = self._parse_config(f.read())

                for section in config.sections():

                    if "Interface" in section:
                        yield WireGuardInterfaceRecord(
                            name=basename(config_path).replace(".conf", "").replace(".netdev", ""),
                            address=config.get(section, "Address").split("/")[0],
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

    @internal
    def _parse_config(self, content: str) -> ConfigParser:
        """
        Parses WireGuard config ini stanza files using Python's ConfigParser module.
        We create our own MultiDict definition from an ordered dict, since we want
        to allow multiple 'Peer' sections. We prepend section names with numbers;
        'Interface', 'Peer1', 'Peer2', 'Peer2', etc.
        This way we prevent duplicate section keys.
        """

        class MultiDict(OrderedDict):
            def __init__(self, *args, **kwargs):
                self._unique = 0
                super().__init__(*args, **kwargs)

            def __setitem__(self, key, val):
                if isinstance(val, dict) and (key == "Peer" or key == "Interface"):
                    self._unique += 1
                    key += str(self._unique)
                super().__setitem__(key, val)

        cp = ConfigParser(defaults=None, dict_type=MultiDict, strict=False)
        cp.read_string(content)
        return cp
