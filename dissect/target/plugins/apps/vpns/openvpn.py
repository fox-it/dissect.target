import itertools
import re
from os.path import basename
from typing import Iterator, Union

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export

COMMON_ELEMENTS = [
    ("string", "name"),  # basename of .conf file
    ("string", "proto"),
    ("string", "dev"),
    ("string", "ca"),
    ("string", "cert"),
    ("string", "key"),
    ("string", "tls_auth"),
    ("string", "status"),
    ("string", "log"),
    ("string", "source"),
]

OpenVPNServer = TargetRecordDescriptor(
    "application/vpn/openvpn/server",
    [
        ("net.ipaddress", "local"),
        ("uint16", "port"),
        ("string", "dh"),
        ("string", "topology"),
        ("string", "server"),
        ("string", "ifconfig_pool_persist"),
        ("string[]", "pushed_options"),
        ("boolean", "client_to_client"),
        ("boolean", "duplicate_cn"),
        *COMMON_ELEMENTS,
    ],
)

OpenVPNClient = TargetRecordDescriptor(
    "application/vpn/openvpn/client",
    [
        ("string[]", "remote"),
        *COMMON_ELEMENTS,
    ],
)


CONFIG_COMMENT_SPLIT_REGEX = re.compile("(#|;)")


class OpenVPNPlugin(Plugin):
    """OpenVPN configuration parser.

    References:
        - man (8) openvpn
    """

    __namespace__ = "openvpn"

    config_globs = [
        # This catches openvpn@, openvpn-client@, and openvpn-server@ systemd configurations
        # Linux
        "/etc/openvpn/*.conf",
        "/etc/openvpn/server/*.conf",
        "/etc/openvpn/client/*.conf",
        # Windows
        "sysvol/Program Files/OpenVPN/config/*.conf",
    ]

    user_config_paths = {
        OperatingSystem.WINDOWS.value: ["OpenVPN/config/*.conf"],
        OperatingSystem.OSX.value: ["Library/Application Support/OpenVPN Connect/profiles/*.conf"],
    }

    def __init__(self, target) -> None:
        super().__init__(target)
        self.configs: list[fsutil.TargetPath] = []
        for path in self.config_globs:
            self.configs.extend(self.target.fs.path().glob(path.lstrip("/")))

        user_paths = self.user_config_paths.get(target.os, [])
        for path, user_details in itertools.product(user_paths, self.target.user_details.all_with_home()):
            self.configs.extend(user_details.home_path.glob(path))

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No OpenVPN configuration files found")

    @export(record=[OpenVPNServer, OpenVPNClient])
    def config(self) -> Iterator[Union[OpenVPNServer, OpenVPNClient]]:
        """Parses config files from openvpn interfaces."""

        for config_path in self.configs:
            config = _parse_config(config_path.read_text())

            name = basename(config_path).replace(".conf", "")
            proto = config.get("proto", "udp")  # Default is UDP
            dev = config.get("dev")
            ca = _unquote(config.get("ca"))
            cert = _unquote(config.get("cert"))
            key = _unquote(config.get("key"))
            tls_auth = config.get("tls-auth", "")
            # The format of tls-auth is 'tls-auth ta.key <NUM>'.
            # NUM is either 0 or 1 depending on whether the configuration
            # is for the client or server, and that does not interest us
            # This gets rid of the number at the end, while still supporting spaces
            tls_auth = _unquote(" ".join(tls_auth.split(" ")[:-1]))
            status = config.get("status")
            log = config.get("log")

            if "client" in config:
                remote = config.get("remote", [])
                # In cases when there is only a single remote,
                # we want to return it as its own list
                if isinstance(remote, str):
                    remote = [remote]

                yield OpenVPNClient(
                    name=name,
                    proto=proto,
                    dev=dev,
                    ca=ca,
                    cert=cert,
                    key=key,
                    tls_auth=tls_auth,
                    status=status,
                    log=log,
                    remote=remote,
                    source=config_path,
                    _target=self.target,
                )
            else:
                pushed_options = config.get("push", [])
                # In cases when there is only a single push,
                # we want to return it as its own list
                if isinstance(pushed_options, str):
                    pushed_options = [pushed_options]
                pushed_options = [_unquote(opt) for opt in pushed_options]
                # Defaults here are taken from `man (8) openvpn`
                yield OpenVPNServer(
                    name=name,
                    proto=proto,
                    dev=dev,
                    ca=ca,
                    cert=cert,
                    key=key,
                    tls_auth=tls_auth,
                    status=status,
                    log=log,
                    local=config.get("local", "0.0.0.0"),
                    port=int(config.get("port", "1194")),
                    dh=_unquote(config.get("dh")),
                    topology=config.get("topology"),
                    server=config.get("server"),
                    ifconfig_pool_persist=config.get("ifconfig-pool-persist"),
                    pushed_options=pushed_options,
                    client_to_client=config.get("client-to-client", False),
                    duplicate_cn=config.get("duplicate-cn", False),
                    source=config_path,
                    _target=self.target,
                )


def _parse_config(content: str) -> dict[str, Union[str, list[str]]]:
    """Parses Openvpn config  files"""
    lines = content.splitlines()
    res = {}

    for line in lines:
        # As per man (8) openvpn, lines starting with ; or # are comments
        if line and not line.startswith((";", "#")):
            key, *value = line.split(" ", 1)
            value = value[0] if value else ""
            # This removes all text after the first comment
            value = CONFIG_COMMENT_SPLIT_REGEX.split(value, 1)[0].strip()
            if old_value := res.get(key):
                if not isinstance(old_value, list):
                    old_value = [old_value]
                res[key] = old_value + [value]
            else:
                res[key] = value
    return res


def _unquote(content: str) -> str:
    return content.strip("\"'")
