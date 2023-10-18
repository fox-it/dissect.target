import logging
from datetime import datetime
from pathlib import Path
from typing import Iterator, Union

from Crypto.PublicKey import ECC, RSA
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.plugin import Plugin, export

log = logging.getLogger(__name__)

SshHostKeyRecord = TargetRecordDescriptor(
    "application/putty/known_host",
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
    "application/putty/saved_session",
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
    """Extract artifacts from the PuTTY client.

    NOTE:T
        - Does not parse $HOME/.putty/randomseed (GNU/Linux)
          and HKCU\\Software\\SimonTatham\\PuTTY\\RandSeedFile (Windows)

    Resources:
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/0.78/puttydoc.txt
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/faq.html#faq-settings
    """

    __namespace__ = "putty"

    def __init__(self, target):
        super().__init__(target)

        self.regf_installs, self.path_installs = self._detect_putty()

    def _detect_putty(self) -> list[list[RegistryKey], list[TargetPath]]:
        regf_installs, path_installs = [], []

        if self.target.has_function("registry"):
            regf_installs = list(self.target.registry.keys("HKCU\\Software\\SimonTatham\\PuTTY"))

        for user_details in self.target.user_details.all_with_home():
            if (putty_path := user_details.home_path.joinpath(".putty")).exists():
                path_installs.append(putty_path)

        return regf_installs, path_installs

    def check_compatible(self) -> None:
        if not any(self.regf_installs + self.path_installs):
            raise UnsupportedPluginError("No PuTTY installations found")

    @export(record=SshHostKeyRecord)
    def known_hosts(self) -> Iterator[SshHostKeyRecord]:
        """Parse PuTTY saved SshHostKeys."""

        for regf_install in self.regf_installs:
            yield from self._regf_known_hosts(regf_install)

        for path_install in self.path_installs:
            yield from self._path_known_hosts(path_install)

    def _regf_known_hosts(self, putty_key: RegistryKey) -> Iterator[SshHostKeyRecord]:
        """Parse PuTTY traces in Windows registry."""

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
                source=windows_path(ssh_host_keys.path),  # Technically this is a registry path
                _target=self.target,
            )

    def _path_known_hosts(self, putty_path: TargetPath) -> Iterator[SshHostKeyRecord]:
        """Parse PuTTY traces in ``.putty`` folders"""
        ssh_host_keys_path = putty_path.joinpath("sshhostkeys")

        if ssh_host_keys_path.exists():
            ts = ssh_host_keys_path.stat().st_mtime

            for line in open_decompress(ssh_host_keys_path, "rt"):
                parts = line.split()
                key_type, host = parts[0].split("@")
                port, host = host.split(":")

                yield SshHostKeyRecord(
                    ts=ts,
                    key_type=key_type,
                    host=host,
                    port=port,
                    public_key=construct_public_key(key_type, parts[1]),
                    source=ssh_host_keys_path,
                    _target=self.target,
                )

    @export(record=SessionRecord)
    def sessions(self) -> Iterator[SessionRecord]:
        """Parse PuTTY saved session configuration files."""

        for regf_install in self.regf_installs:
            yield from self._regf_sessions(regf_install)

        for path_install in self.path_installs:
            yield from self._path_sessions(path_install)

    def _regf_sessions(self, putty_key: RegistryKey) -> Iterator[SessionRecord]:
        try:
            sessions = putty_key.subkey("Sessions")
        except RegistryKeyNotFoundError:
            return

        for session in sessions.subkeys():
            cfg = {s.name: s.value for s in session.values()}
            yield from self._build_session_record(session.ts, session.name, windows_path(session.path), cfg)

    def _path_sessions(self, putty_path: TargetPath) -> Iterator[SessionRecord]:
        sessions_dir = putty_path.joinpath("sessions")
        if sessions_dir.exists():
            for session in sessions_dir.glob("*"):
                if session.is_file():
                    cfg = dict(map(str.strip, line.split("=", maxsplit=1)) for line in session.open("rt").readlines())
                    yield from self._build_session_record(session.stat().st_mtime, session.name, session, cfg)

    def _build_session_record(self, ts, name: Union[float, datetime], source: Path, cfg: dict) -> SessionRecord:
        host, user = parse_host_user(cfg.get("HostName"), cfg.get("UserName"))

        yield SessionRecord(
            ts=ts,
            session_name=name,
            protocol=cfg.get("Protocol"),
            host=host,
            user=user,
            port=cfg.get("PortNumber"),
            remote_command=cfg.get("RemoteCommand"),
            port_forward=cfg.get("PortForwardings"),
            manual_ssh_host_keys=cfg.get("SSHManualHostKeys"),
            source=source,
            _target=self.target,
        )


def parse_host_user(host: str, user: str) -> tuple[str, str]:
    """Parse host and user from PuTTY hostname component."""
    if "@" in host:
        parsed_user, parsed_host = host.split("@")
        user = user or parsed_user
        host = parsed_host

    return host, user


def construct_public_key(key_type: str, iv: str) -> str:
    """Returns OpenSSH format public key calculated from PuTTY SshHostKeys format.

    PuTTY stores raw public key components instead of OpenSSH-formatted public keys
    or fingerprints. With RSA public keys the exponent and modulus are stored.
    With ECC keys the x and y prime coordinates are stored together with the curve type.

    Currently supports ``ssh-ed25519``, ``ecdsa-sha2-nistp256`` and ``rsa2`` key types.

    NOTE:
        - Sha256 fingerprints of the reconstructed public keys are currently not generated.
        - More key types could be supported in the future.

    Resources:
        - https://github.com/github/putty/blob/master/contrib/kh2reg.py
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
        - https://github.com/mkorthof/reg2kh
    """

    if key_type == "ssh-ed25519":
        x, y = iv.split(",")
        key = ECC.construct(curve="ed25519", point_x=int(x, 16), point_y=int(y, 16))
        return key.public_key().export_key(format="OpenSSH").split()[-1]

    if key_type == "ecdsa-sha2-nistp256":
        _, x, y = iv.split(",")
        key = ECC.construct(curve="NIST P-256", point_x=int(x, 16), point_y=int(y, 16))
        return key.public_key().export_key(format="OpenSSH").split()[-1]

    if key_type == "rsa2":
        exponent, modulus = iv.split(",")
        key = RSA.construct((int(modulus, 16), int(exponent, 16)))
        return key.public_key().export_key(format="OpenSSH").decode("utf-8").split()[-1]

    log.warning("Could not reconstruct public key: type %s not implemented.", key_type)
    return iv
