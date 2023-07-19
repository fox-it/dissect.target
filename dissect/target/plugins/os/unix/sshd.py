import logging
from typing import Iterator, Tuple, Union

from dissect.target import Target
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

SSHD_BOOLEAN_VALUES = (
    "yes",
    "no",
)

SSHD_BOOLEAN_FIELDS = (
    "AllowAgentForwarding",
    "DebianBanner",
    "ExposeAuthInfo",
    "GatewayPorts",
    "GSSAPICleanupCredentials",
    "GSSAPIStrictAcceptorCheck",
    "GSSAPIKeyExchange",
    "GSSAPIStrictAcceptorCheck",
    "GSSAPIStoreCredentialsOnRekey",
    "HostbasedUsesNameFromPacketOnly",
    "IgnoreUserKnownHosts",
    "KbdInteractiveAuthentication",
    "KerberosAuthentication",
    "KerberosGetAFSToken",
    "KerberosOrLocalPasswd",
    "KerberosTicketCleanup",
    "PasswordAuthentication",
    "PermitEmptyPasswords",
    "PermitTTY",
    "PermitUserRC",
    "PrintLastLog",
    "PrintMotd",
    "PubkeyAuthentication",
    "StreamLocalBindUnlink",
    "StrictModes",
    "TCPKeepAlive",
    "UsePAM",
    "X11Forwarding",
    "X11UseLocalhost",
)

SSHD_INTEGER_FIELDS = (
    "ClientAliveInterval",
    "LoginGraceTime",
    "MaxAuthTries",
    "MaxSessions",
    "Port",
    "X11DisplayOffset",
)

SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS = (
    "AcceptEnv",
    "Include",
    "ListenAddress",
    "PermitListen",
    "PermitListen",
    "Port",
)


log = logging.getLogger(__name__)


class SSHServerPlugin(Plugin):
    __namespace__ = "sshd"

    SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

    def __init__(self, target: Target):
        super().__init__(target)

        self.sshd_config_path = self.target.fs.path(self.SSHD_CONFIG_PATH)

    def check_compatible(self) -> bool:
        return self.sshd_config_path.is_file()

    @export(record=DynamicDescriptor(["datetime", "path"]))
    def config(self) -> Iterator[DynamicDescriptor]:
        """Parse all fields in the SSH server config in /etc/ssh/sshd_config.

        This function parses each line (not starting with '#') as a key-value pair, delimited by whitespace.
        The values of these fields can be one of three types: string, integer and boolean (string is the default).

        We provide two lists that define the integer and boolean fields (SSHD_INTEGER_FIELDS and SSHD_BOOLEAN_FIELDS).

        The fields in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS can be defined multiple times.
        We set their type to a list of the underlying value (e.g. varint[] for the Port field).

        This parser does not (yet) follow Include directives.

        Resources:
            - https://github.com/openssh/openssh-portable
            - https://www.man7.org/linux/man-pages/man5/sshd_config.5.html
        """

        record_fields = [
            ("datetime", "mtime"),
            ("path", "source"),
        ]

        config = {}
        with self.sshd_config_path.open("r") as h_file:
            for line in h_file:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                # Passing None as the first argument to split, means splitting on all (ASCII) whitespace.
                key, value = line.split(None, 1)
                value, value_record_type = _parse_sshd_config_value(key, value)

                if key not in config and key in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS:
                    config[key] = [value]
                    record_fields.append((f"{value_record_type}[]", key))

                elif key not in config and key not in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS:
                    config[key] = value
                    record_fields.append((value_record_type, key))

                elif key in config and key in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS:
                    config[key].append(value)

                elif key in config and key not in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS:
                    self.target.log.warning(f"Overwriting sshd_config value: '{key} {value}'.")
                    config[key] = value

        yield TargetRecordDescriptor("unix/sshd/config", record_fields)(
            mtime=self.sshd_config_path.stat().st_mtime,
            source=self.sshd_config_path,
            **config,
        )


def _parse_sshd_config_value(key: str, value: str) -> Tuple[Union[str, bool, int], str]:
    """Convert a value to either a string, bool or integer, based on the corresponding key.

    If we cannot convert the given value to the expected type, we log a warning and return a string.
    We return the value (as the expected type) and the name of the type.
    """

    if key in SSHD_BOOLEAN_FIELDS:
        if value in SSHD_BOOLEAN_VALUES:
            return value == SSHD_BOOLEAN_VALUES[0], "boolean"
        else:
            log.warning(f"Invalid boolean value found in sshd_config: '{key} {value}'.")
            return value, "string"

    elif key in SSHD_INTEGER_FIELDS:
        try:
            return int(value), "varint"
        except ValueError:
            log.warning(f"Invalid int value found in sshd_config: '{key} {value}'.")
            return value, "string"

    else:
        return value, "string"
