from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional, Union

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.apps.ssh.openssh import find_sshd_directory

if TYPE_CHECKING:
    from dissect.target.plugins.general.config import ConfigurationTreePlugin

SSHD_BOOLEAN_VALUES = (
    "yes",
    "no",
)

SSHD_BOOLEAN_FIELDS = (
    "AllowAgentForwarding",
    "DebianBanner",
    "DisableForwarding",
    "ChallengeResponseAuthentication",
    "ExposeAuthInfo",
    "GSSAPIAuthentication",
    "GSSAPICleanupCredentials",
    "GSSAPICleanupCredentials",
    "GSSAPIStrictAcceptorCheck",
    "GSSAPIStoreCredentialsOnRekey",
    "GSSAPIKeyExchange",
    "GSSAPIStrictAcceptorCheck",
    "GSSAPIStoreCredentialsOnRekey",
    "HostbasedAuthentication",
    "HostbasedUsesNameFromPacketOnly",
    "IgnoreUserKnownHosts",
    "KbdInteractiveAuthentication",
    "KeepAlive",
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
    "ClientAliveCountMax",
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
    "PermitOpen",
    "Port",
)


class SSHServerPlugin(Plugin):
    __namespace__ = "sshd"

    def __init__(self, target: Target):
        super().__init__(target)
        self.sshd_directory = find_sshd_directory(target)
        self.sshd_config_path = self.sshd_directory.joinpath("sshd_config")

    def check_compatible(self) -> None:
        if not self.sshd_config_path.exists():
            raise UnsupportedPluginError("No sshd config found")

    @export(record=DynamicDescriptor(["datetime", "path"]))
    def config(self) -> Iterator[DynamicDescriptor]:
        """Parse all fields in the SSH server config in /etc/ssh/sshd_config.

        This function parses each line (not starting with '#') as a key-value
        pair, delimited by whitespace. The values of these fields can be one
        of three types: string, integer and boolean (string is the default).

        We provide two lists that define the integer and boolean fields
        (SSHD_INTEGER_FIELDS and SSHD_BOOLEAN_FIELDS).

        The fields in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS can be
        defined multiple times. We set their type to a list of the
        underlying value (e.g. varint[] for the Port field).

        This parser does not (yet) follow Include directives.

        Resources:
            - https://github.com/openssh/openssh-portable
            - https://www.man7.org/linux/man-pages/man5/sshd_config.5.html
        """

        record_fields = [
            ("datetime", "mtime"),
            ("path", "source"),
        ]

        config_tree: ConfigurationTreePlugin = self.target.config_tree

        # Parse sshd_config
        sshd_config = config_tree(
            path=self.sshd_config_path,
            collapse=SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS,
            collapse_inverse=True,
            as_dict=True,
        )

        if _ := sshd_config.get("Include"):
            # Gather included config
            pass

        config = {}
        for key, value in sshd_config.items():
            if isinstance(value, dict):
                # A match statement, ignore for now
                continue
            _type, _value = _determine_type_and_value(key, value)

            config[key] = _value
            record_fields.append((_type, key))

        yield TargetRecordDescriptor("application/openssh/sshd_config", record_fields)(
            mtime=self.sshd_config_path.stat().st_mtime, source=self.sshd_config_path, **config, _target=self.target
        )


def _determine_type_and_value(key: str, value: str) -> tuple[str, Any]:
    _type = "string"
    _value = value

    _unpack = None
    if key in SSHD_INTEGER_FIELDS:
        _type = "varint"
        _unpack = int
    elif key in SSHD_BOOLEAN_FIELDS and _value.lower() in SSHD_BOOLEAN_VALUES:
        _type = "boolean"
        _unpack = _convert_bool
    else:
        _type = "string"

    if multiple_fields := (key in SSHD_MULTIPLE_DEFINITIONS_ALLOWED_FIELDS):
        _value = _value if isinstance(_value, list) else [_value]

    try:
        _value = _convert_function(_value, _unpack)
    except Exception:
        # Something went wrong, restore default type
        _type = "string"

    if multiple_fields:
        # The type can still be a list, so in that case, we append `[]`
        _type = f"{_type}[]"

    return _type, _value


def _convert_function(value: Union[str, list], unpack_function: Optional[Callable]) -> Union[list[Any], Any]:
    if isinstance(value, list):
        return [unpack_function(val) for val in value]
    return unpack_function(value)


def _convert_bool(value: str) -> bool:
    return value.lower() == SSHD_BOOLEAN_VALUES[0]
