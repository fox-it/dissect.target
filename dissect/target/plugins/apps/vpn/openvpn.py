from __future__ import annotations

import io
import itertools
from itertools import product
from typing import TYPE_CHECKING, Final

from dissect.target.exceptions import ConfigurationParsingError, UnsupportedPluginError
from dissect.target.helpers.configutil import Default, ListUnwrapper, _update_dictionary
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers import fsutil
    from dissect.target.target import Target

COMMON_ELEMENTS = [
    ("string", "name"),  # basename of .conf file
    ("string", "proto"),
    ("string", "dev"),
    ("string", "ca"),
    ("string", "cert"),
    ("string", "key"),
    ("boolean", "redacted_key"),
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


class OpenVPNParser(Default):
    def __init__(self, *args, **kwargs):
        boolean_fields = OpenVPNServer.getfields("boolean") + OpenVPNClient.getfields("boolean")
        self.boolean_field_names = {field.name.replace("_", "-") for field in boolean_fields}

        super().__init__(*args, separator=(r"\s",), collapse=["key", "ca", "cert"], **kwargs)

    def parse_file(self, fh: io.TextIOBase) -> None:
        root = {}
        iterator = self.line_reader(fh)
        for line in iterator:
            if line.startswith("<"):
                key = line.strip().strip("<>")
                value = self._read_blob(iterator)
                _update_dictionary(root, key, value)
                continue

            self._parse_line(root, line)

        self.parsed_data = ListUnwrapper.unwrap(root)

    def _read_blob(self, lines: Iterator[str]) -> str | list[dict]:
        """Read the whole section between ``<data></data>`` sections."""
        output = ""
        with io.StringIO() as buffer:
            for line in lines:
                if "</" in line:
                    break

                buffer.write(line)
            output = buffer.getvalue()

        # Check for connection profile blocks
        if not output.startswith("-----"):
            profile_dict = {}
            for line in output.splitlines():
                self._parse_line(profile_dict, line)

            # We put it as a list as _update_dictionary appends data in a list.
            output = [profile_dict]

        return output

    def _parse_line(self, root: dict, line: str) -> None:
        key, *value = self.SEPARATOR.split(line, 1)
        # Unquote data
        value = value[0].strip() if value else ""

        value = value.strip("'\"")

        if key in self.boolean_field_names:
            value = True

        _update_dictionary(root, key, value)


class OpenVPNPlugin(Plugin):
    """OpenVPN configuration parser.

    References:
        - man (8) openvpn
    """

    __namespace__ = "openvpn"

    config_globs = (
        # This catches openvpn@, openvpn-client@, and openvpn-server@ systemd configurations
        # Linux
        "/etc/openvpn/",
        # Windows
        "sysvol/Program Files/OpenVPN/config/",
    )

    user_config_paths: Final[dict[str, list[str]]] = {
        OperatingSystem.WINDOWS.value: ["OpenVPN/config/"],
        OperatingSystem.OSX.value: ["Library/Application Support/OpenVPN Connect/profiles/"],
    }

    def __init__(self, target: Target):
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

    def _load_config(self, parser: OpenVPNParser, config_path: fsutil.TargetPath) -> dict | None:
        with config_path.open("rt") as file:
            try:
                parser.parse_file(file)
            except ConfigurationParsingError as e:
                # Couldn't parse file, continue
                self.target.log.info("An issue occurred during parsing of %s, continuing", config_path)
                self.target.log.debug("", exc_info=e)
                return None

        return parser.parsed_data

    @export(record=[OpenVPNServer, OpenVPNClient])
    @arg("--export-key", action="store_true", help="export private keys to records")
    def config(self, export_key: bool = False) -> Iterator[OpenVPNServer | OpenVPNClient]:
        """Parses config files from openvpn interfaces."""
        # We define the parser here so we can reuse it
        parser = OpenVPNParser()

        for config_path in self.configs:
            config = self._load_config(parser, config_path)

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
                common_elements.update({"key": None})
                common_elements.update({"redacted_key": True})

            tls_auth = config.get("tls-auth", "")
            # The format of tls-auth is 'tls-auth ta.key <NUM>'.
            # NUM is either 0 or 1 depending on whether the configuration
            # is for the client or server, and that does not interest us
            # This gets rid of the number at the end, while still supporting spaces
            tls_auth = " ".join(tls_auth.split(" ")[:-1]).strip("'\"")

            common_elements.update({"tls_auth": tls_auth})

            if "client" in config:
                remote = config.get("remote", [])

                yield OpenVPNClient(
                    **common_elements,
                    remote=remote,
                )
            else:
                # Defaults here are taken from `man (8) openvpn`
                yield OpenVPNServer(
                    **common_elements,
                    local=config.get("local", "0.0.0.0"),
                    port=int(config.get("port", "1194")),
                    dh=config.get("dh"),
                    topology=config.get("topology"),
                    server=config.get("server"),
                    ifconfig_pool_persist=config.get("ifconfig-pool-persist"),
                    pushed_options=config.get("push", []),
                    client_to_client=config.get("client-to-client", False),
                    duplicate_cn=config.get("duplicate-cn", False),
                )
