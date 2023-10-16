import logging
from configparser import ConfigParser
from typing import Iterator, Union

from Crypto.PublicKey import ECC, RSA

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.regutil import RegfKey, VirtualKey
from dissect.target.plugin import Plugin, export

log = logging.getLogger(__name__)

SshHostKeyRecord = TargetRecordDescriptor(
    "putty/known_host",
    [
        ("datetime", "ts"),
        ("string", "host"),
        ("varint", "port"),
        ("string", "key_type"),
        ("string", "public_key"),
        ("path", "source"),
    ],
)

SessionRecord = TargetRecordDescriptor(
    "putty/saved_session",
    [
        ("datetime", "ts"),
        ("string", "session_name"),
        ("string", "protocol"),
        ("string", "host"),
        ("string", "user"),
        ("varint", "port"),
        ("string", "remote_command"),
        ("string", "port_forward"),
        ("string", "manual_ssh_host_keys"),
        ("path", "source"),
    ],
)


class PuTTYPlugin(Plugin):
    """Extract artifacts from a PuTTY Windows or Linux client.

    TODO:
        - Parse $HOME/.putty/randomseed (GNU/Linux)
          and HKCU\\Software\\SimonTatham\\PuTTY\\RandSeedFile (Windows)
        - Return UserTargetRecordDescriptors
        - Calculate fingerprint hashes of public keys

    Resources:
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/0.78/puttydoc.txt
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/faq.html#faq-settings
    """

    __namespace__ = "putty"

    def __init__(self, target):
        super().__init__(target)

        self.win_key = "HKCU\\Software\\SimonTatham\\PuTTY"
        self.linux_path = ".putty/"

        self.installs = self._detect_putty()

    def _detect_putty(self) -> list[TargetPath]:
        installs = []

        if self.target.os == "windows" and (keys := list(self.target.registry.keys(self.win_key))):
            installs = keys

        elif self.target.os == "linux" or self.target.os == "unix":
            for user_details in self.target.user_details.all_with_home():
                if (putty_path := user_details.home_path.joinpath(self.linux_path)).exists():
                    installs.append(putty_path)

        return installs

    def check_compatible(self) -> bool:
        return any(self.installs)

    @export(record=SshHostKeyRecord)
    def known_hosts(self) -> Iterator[SshHostKeyRecord]:
        """Parse PuTTY saved SshHostKeys."""
        for putty_install in self.installs:
            if self.target.os == "windows":
                yield from self._windows_known_hosts(putty_install)
            else:
                yield from self._linux_known_hosts(putty_install)

    def _windows_known_hosts(self, putty_key: RegfKey) -> Iterator[Union[SshHostKeyRecord, None]]:
        """Parse PuTTY traces in Windows registry."""
        if type(putty_key) not in [RegfKey, VirtualKey]:
            raise ValueError(f"Cannot handle type {type(putty_key)}")

        ssh_host_keys = None

        try:
            ssh_host_keys = putty_key.subkey("SshHostKeys")
        except RegistryKeyNotFoundError:
            return

        for entry in ssh_host_keys.values():
            key_type, host = entry.name.split("@")
            port, host = host.split(":")
            yield SshHostKeyRecord(
                ts=ssh_host_keys.ts,
                key_type=key_type,
                host=host,
                port=port,
                public_key=construct_public_key(key_type, entry.value),
                source=str(ssh_host_keys.path),
                _target=self.target,
            )

    def _linux_known_hosts(self, putty_path: TargetPath) -> Iterator[Union[SshHostKeyRecord, None]]:
        """Parse linux traces in .putty folders"""
        ssh_host_keys_path = putty_path.joinpath("sshhostkeys")
        if not ssh_host_keys_path.exists():
            return

        for line in open_decompress(ssh_host_keys_path, "rt"):
            line = line.strip()
            meta = line.split(" ")[0]
            key_type, host = meta.split("@")
            port, host = host.split(":")

            yield SshHostKeyRecord(
                ts=ssh_host_keys_path.stat().st_mtime,
                key_type=key_type,
                host=host,
                port=port,
                public_key=construct_public_key(key_type, line.split(" ")[1]),
                source=ssh_host_keys_path,
                _target=self.target,
            )

    @export(record=SessionRecord)
    def sessions(self) -> Iterator[SessionRecord]:
        """Parse PuTTY saved session configuration files."""
        for putty_install in self.installs:
            if self.target.os == "windows":
                yield from self._windows_sessions(putty_install)
            else:
                yield from self._linux_sessions(putty_install)

    def _windows_sessions(self, putty_key: RegfKey) -> Iterator[SessionRecord]:
        if type(putty_key) not in [RegfKey, VirtualKey]:
            raise ValueError(f"Cannot handle type {type(putty_key)}")

        sessions = None
        try:
            sessions = putty_key.subkey("Sessions")
        except RegistryKeyNotFoundError:
            return

        for session in sessions.subkeys():
            cfg = {s.name: s.value for s in session.values()}

            host, user = parse_host_user(cfg.get("HostName"), cfg.get("UserName"))

            yield SessionRecord(
                ts=session.ts,
                session_name=session.name,
                protocol=cfg.get("Protocol"),
                host=host,
                user=user,
                port=cfg.get("PortNumber"),
                remote_command=cfg.get("RemoteCommand"),
                port_forward=cfg.get("PortForwardings"),
                manual_ssh_host_keys=cfg.get("SSHManualHostKeys"),
                source=str(session.path),
                _target=self.target,
            )

    def _linux_sessions(self, putty_path: TargetPath) -> Iterator[SessionRecord]:
        sessions_dir = putty_path.joinpath("sessions")
        if not sessions_dir.exists:
            return

        for session in sessions_dir.glob("*"):
            cfg = ConfigParser(strict=False, allow_no_value=True, delimiters=("=",), interpolation=None)
            cfg.read_string("[global]\n" + session.read_text())

            host, user = parse_host_user(cfg["global"].get("HostName"), cfg["global"].get("UserName"))

            yield SessionRecord(
                ts=session.stat().st_mtime,
                session_name=session.name,
                protocol=cfg["global"].get("Protocol"),
                host=host,
                user=user,
                port=cfg["global"].get("PortNumber"),
                remote_command=cfg["global"].get("RemoteCommand"),
                port_forward=cfg["global"].get("PortForwardings"),
                manual_ssh_host_keys=cfg["global"].get("SSHManualHostKeys"),
                source=session,
                _target=self.target,
            )


def parse_host_user(host: str, user: str) -> tuple[str, str]:
    if "@" in host and not user:
        user = host.split("@")[0]
        host = host.split("@")[-1]
    return host, user


def decode_hex(hex: str) -> int:
    """Decode the hex format used by PuTTY to integers."""
    if hex.startswith("0x"):
        hex = hex[2:]
    return int(hex, 16)


def construct_public_key(key_type: str, iv: str) -> str:
    """Returns OpenSSH format public key calculated from PuTTY SshHostKeys format.

    PuTTY stores raw public key components instead of OpenSSH-formatted public keys
    or fingerprints. With RSA public keys the exponent and modulus are stored.
    With ECC keys the x and y prime coordinates are stored together with the curve type.

    Currently supports ``ssh-ed25519``, ``ecdsa-sha2-nistp256`` and ``rsa2`` key types.

    TODO:
        - Generate sha256 fingerprints of the reconstructed public keys.
        - Add more supported key types.

    Resources:
        - https://github.com/github/putty/blob/master/contrib/kh2reg.py
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
        - https://github.com/mkorthof/reg2kh
    """
    key = False

    if key_type == "ssh-ed25519":
        x, y = iv.split(",")
        key = ECC.construct(curve="ed25519", point_x=decode_hex(x), point_y=decode_hex(y))
        return key.public_key().export_key(format="OpenSSH").split(" ")[-1].strip()

    elif key_type == "ecdsa-sha2-nistp256":
        curve, x, y = iv.split(",")
        key = ECC.construct(curve="NIST P-256", point_x=decode_hex(x), point_y=decode_hex(y))
        return key.public_key().export_key(format="OpenSSH").split(" ")[-1].strip()

    elif key_type == "rsa2":
        exponent, modulus = iv.split(",")
        key = RSA.construct((decode_hex(modulus), decode_hex(exponent)))
        return key.public_key().export_key(format="OpenSSH").decode("utf-8").split(" ")[-1].strip()

    log.warning(f"Could not reconstruct public key: type {key_type} not implemented.")
    return iv
