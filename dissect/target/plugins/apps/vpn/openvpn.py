import itertools
import re
from itertools import product
from typing import Iterator, Union

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, arg, export

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
        "/etc/openvpn/",
        # Windows
        "sysvol/Program Files/OpenVPN/config/",
    ]

    user_config_paths = {
        OperatingSystem.WINDOWS.value: ["OpenVPN/config/"],
        OperatingSystem.OSX.value: ["Library/Application Support/OpenVPN Connect/profiles/"],
    }

    def __init__(self, target) -> None:
        super().__init__(target)
        self.configs: list[fsutil.TargetPath] = []
        for base, glob in product(self.config_globs, ["*.conf", "*.ovpn"]):
            self.configs.extend(self.target.fs.path(base).rglob(glob))

        user_paths = self.user_config_paths.get(target.os, [])
        for path, glob, user_details in itertools.product(
            user_paths, ["*.conf", "*.ovpn"], self.target.user_details.all_with_home()
        ):
            self.configs.extend(user_details.home_path.joinpath(path).rglob(glob))

    def check_compatible(self) -> None:
        if not self.configs:
            raise UnsupportedPluginError("No OpenVPN configuration files found")

    @export(record=[OpenVPNServer, OpenVPNClient])
    @arg("--export-key", action="store_true")
    def config(self, export_key: bool = False) -> Iterator[Union[OpenVPNServer, OpenVPNClient]]:
        """Parses config files from openvpn interfaces."""

        for config_path in self.configs:
            open_vpn_config = self.target.config_tree(
                config_path,
                hint="ovpn",
                as_dict=True,
                collapse=["key", "ca", "cert"],
            )
            config = _parse_config(open_vpn_config)

            common_elements = {
                "name": config_path.stem,
                "proto": config.get("proto", "udp"),  # Default is UDP
                "dev": config.get("dev"),
                "ca": config.get("ca"),
                "cert": config.get("cert"),
                "key": config.get("key"),
                "status": config.get("status"),
                "log": config.get("log"),
                "source": config_path,
                "_target": self.target,
            }

            if not export_key and "PRIVATE KEY" in common_elements.get("key"):
                common_elements.update({"key": "REDACTED"})

            tls_auth = config.get("tls-auth", "")
            # The format of tls-auth is 'tls-auth ta.key <NUM>'.
            # NUM is either 0 or 1 depending on whether the configuration
            # is for the client or server, and that does not interest us
            # This gets rid of the number at the end, while still supporting spaces
            tls_auth = _unquote(" ".join(tls_auth.split(" ")[:-1]))

            common_elements.update({"tls_auth": tls_auth})

            if "client" in config:
                remote = config.get("remote", [])

                yield OpenVPNClient(
                    **common_elements,
                    remote=remote,
                )
            else:
                pushed_options = config.get("push", [])
                # Defaults here are taken from `man (8) openvpn`
                yield OpenVPNServer(
                    **common_elements,
                    local=config.get("local", "0.0.0.0"),
                    port=int(config.get("port", "1194")),
                    dh=_unquote(config.get("dh")),
                    topology=config.get("topology"),
                    server=config.get("server"),
                    ifconfig_pool_persist=config.get("ifconfig-pool-persist"),
                    pushed_options=pushed_options,
                    client_to_client=config.get("client-to-client", False),
                    duplicate_cn=config.get("duplicate-cn", False),
                )


def _parse_config(content: dict[str, str]) -> dict[str, Union[str, list[str]]]:
    """Parses Openvpn config  files"""
    boolean_fields = OpenVPNServer.getfields("boolean") + OpenVPNClient.getfields("boolean")
    boolean_field_names = set(field.name for field in boolean_fields)
    for key, value in content.items():
        if key in boolean_field_names:
            content.update({key: value == ""})

    return content


def _unquote(content: str) -> str:
    return content.strip("\"'")
