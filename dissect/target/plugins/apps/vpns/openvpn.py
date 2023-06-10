from os.path import basename
from typing import Iterator, Union

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, OperatingSystem


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


class OpenVPNPlugin(Plugin):
    """OpenVPN configuration parser.

    References:
        - man (8) openvpn
    """

    __namespace__ = "openvpn"

    """
    """

    config_globs = [
        # This catches openvpn@, openvpn-client@, and openvpn-server@ systemd configurations
        # Linux
        "/etc/openvpn/*.conf",
        "/etc/openvpn/server/*.conf",
        "/etc/openvpn/client/*.conf",
        # Windows
        "sysvol/Program Files/OpenVPN/config/*.conf",
    ]

    def __init__(self, target) -> None:
        super().__init__(target)
        self.configs = []
        for path in self.config_globs:
            cfgs = list(self.target.fs.path().glob(path.lstrip("/")))
            if len(cfgs) > 0:
                for cfg in cfgs:
                    self.configs.append(cfg)

        if target.os == OperatingSystem.WINDOWS.value:
            for user_details in self.target.user_details.all_with_home():
                for cfg in user_details.home_path.glob("OpenVPN/config/*.conf"):
                    self.configs.append(cfg)

        if target.os == OperatingSystem.OSX.value:
            for user_details in self.target.user_details.all_with_home():
                for cfg in user_details.home_path.glob("Library/Application Support/OpenVPN Connect/profiles/*.conf"):
                    self.configs.append(cfg)

    def check_compatible(self) -> bool:
        if len(self.configs) > 0:
            return True

    @export(record=[OpenVPNServer, OpenVPNClient])
    def config(self) -> Iterator[Union[OpenVPNServer, OpenVPNClient]]:
        """Parses config files from openvpn interfaces."""

        for config_path in self.configs:
            config = _parse_config(config_path.read_text())

            name = basename(config_path).replace(".conf", "")
            proto = config.get("proto", "udp")  # Default is UDP
            dev = config.get("dev")
            ca = config.get("ca").strip('"').strip("'")
            cert = config.get("cert").strip('"').strip("'")
            key = config.get("key").strip('"').strip("'")
            tls_auth = config.get("tls-auth", "")
            # The format of tls-auth is 'tls-auth ta.key <NUM>'.
            # NUM is either 0 or 1 depending on whether the configuration
            # is for the client or server, and that does not interest us
            # This gets rid of the number at the end, while still supporting spaces
            tls_auth = " ".join(tls_auth.split(" ")[:-1]).strip('"').strip("'")
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
                pushed_options = [opt.strip('"').strip("'") for opt in pushed_options]
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
                    dh=config.get("dh").strip('"').strip("'"),
                    topology=config.get("topology"),
                    server=config.get("server"),
                    ifconfig_pool_persist=config.get("ifconfig-pool-persist"),
                    pushed_options=pushed_options,
                    client_to_client=config.get("client-to-client", False),
                    duplicate_cn=config.get("duplicate-cn", False),
                    source=config_path,
                    _target=self.target,
                )


def _parse_config(content: str) -> dict:
    """Parses Openvpn config  files"""
    lines = content.splitlines()
    res = {}

    for line in lines:
        # As per man (8) openvpn, lines starting with ; or # are comments
        if line and not (line.startswith(";") or line.startswith("#")):
            key, *value = line.split(" ", 1)
            value = next(iter(value), "")
            value = value.split("#", 1)[0].strip()
            if old_key := res.get(key):
                if not isinstance(old_key, list):
                    old_key = [old_key]
                res[key] = [*old_key, value]
            else:
                res[key] = value
    return res
