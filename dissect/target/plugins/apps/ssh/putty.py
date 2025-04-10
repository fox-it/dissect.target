from __future__ import annotations

import logging
from base64 import b64decode
from typing import TYPE_CHECKING

try:
    from Crypto.PublicKey import ECC, RSA

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from flow.record.fieldtypes import posix_path, windows_path

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.ssh.ssh import (
    KnownHostRecord,
    SSHPlugin,
    calculate_fingerprints,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from pathlib import Path

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

log = logging.getLogger(__name__)

PuTTYUserRecordDescriptor = create_extended_descriptor([UserRecordDescriptorExtension])
PuTTYSessionRecord = PuTTYUserRecordDescriptor(
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
        ("path", "path"),
    ],
)


class PuTTYPlugin(SSHPlugin):
    """Extract artifacts from the PuTTY client.

    NOTE:
        - Does not parse ``$HOME/.putty/randomseed`` (GNU/Linux)
          and ``HKCU\\Software\\SimonTatham\\PuTTY\\RandSeedFile`` (Windows)

    Resources:
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/0.78/puttydoc.txt
        - http://www.chiark.greenend.org.uk/~sgtatham/putty/faq.html#faq-settings
    """

    __namespace__ = "putty"

    def __init__(self, target: Target):
        super().__init__(target)

        self.regf_installs, self.path_installs = self._detect_putty()

    def _detect_putty(
        self,
    ) -> tuple[list[set[RegistryKey, UserDetails | None]], list[set[TargetPath, UserDetails | None]]]:
        regf_installs, path_installs = [], []

        if self.target.has_function("registry"):
            regf_installs = [
                (key, self.target.registry.get_user_details(key))
                for key in self.target.registry.keys("HKCU\\Software\\SimonTatham\\PuTTY")
            ]

        path_installs = [
            (putty_path, user_details)
            for user_details in self.target.user_details.all_with_home()
            if (putty_path := user_details.home_path.joinpath(".putty")).exists()
        ]

        return regf_installs, path_installs

    def check_compatible(self) -> None:
        if not any(self.regf_installs + self.path_installs):
            raise UnsupportedPluginError("No PuTTY installations found")

    @export(record=KnownHostRecord)
    def known_hosts(self) -> Iterator[KnownHostRecord]:
        """Parse PuTTY saved SshHostKeys."""

        for putty_key, user_details in self.regf_installs:
            yield from self._regf_known_hosts(putty_key, user_details)

        for putty_path, user_details in self.path_installs:
            yield from self._path_known_hosts(putty_path, user_details)

    def _regf_known_hosts(self, putty_key: RegistryKey, user_details: UserDetails) -> Iterator[KnownHostRecord]:
        """Parse PuTTY traces in Windows registry."""

        try:
            ssh_host_keys = putty_key.subkey("SshHostKeys")
        except RegistryKeyNotFoundError:
            return

        for entry in ssh_host_keys.values():
            key_type, host = entry.name.split("@")
            port, host = host.split(":")

            public_key, fingerprints = construct_public_key(key_type, entry.value)

            yield KnownHostRecord(
                mtime_ts=ssh_host_keys.ts,
                host=host,
                port=port,
                key_type=key_type,
                public_key=public_key,
                fingerprint=fingerprints,
                comment="",
                marker=None,
                path=windows_path(ssh_host_keys.path),
                _target=self.target,
                _user=user_details.user if user_details else None,
            )

    def _path_known_hosts(self, putty_path: TargetPath, user_details: UserDetails) -> Iterator[KnownHostRecord]:
        """Parse PuTTY traces in ``.putty`` folders."""
        ssh_host_keys_path = putty_path.joinpath("sshhostkeys")

        if ssh_host_keys_path.exists():
            ts = ssh_host_keys_path.stat().st_mtime

            for line in open_decompress(ssh_host_keys_path, "rt"):
                parts = line.split()
                key_type, host = parts[0].split("@")
                port, host = host.split(":")

                public_key, fingerprints = construct_public_key(key_type, parts[1])

                yield KnownHostRecord(
                    mtime_ts=ts,
                    host=host,
                    port=port,
                    key_type=key_type,
                    public_key=public_key,
                    fingerprint=fingerprints,
                    comment="",
                    marker=None,
                    path=posix_path(ssh_host_keys_path),
                    _target=self.target,
                    _user=user_details.user if user_details else None,
                )

    @export(record=PuTTYSessionRecord)
    def sessions(self) -> Iterator[PuTTYSessionRecord]:
        """Parse PuTTY saved session configuration files."""

        for putty_key, user_details in self.regf_installs:
            yield from self._regf_sessions(putty_key, user_details)

        for putty_path, user_details in self.path_installs:
            yield from self._path_sessions(putty_path, user_details)

    def _regf_sessions(self, putty_key: RegistryKey, user_details: UserDetails) -> Iterator[PuTTYSessionRecord]:
        try:
            sessions = putty_key.subkey("Sessions")
        except RegistryKeyNotFoundError:
            return

        for session in sessions.subkeys():
            cfg = {s.name: s.value for s in session.values()}
            yield from self._build_session_record(
                session.ts, session.name, windows_path(session.path), cfg, user_details
            )

    def _path_sessions(self, putty_path: TargetPath, user_details: UserDetails) -> Iterator[PuTTYSessionRecord]:
        sessions_dir = putty_path.joinpath("sessions")
        if sessions_dir.exists():
            for session in sessions_dir.glob("*"):
                if session.is_file():
                    cfg = dict(map(str.strip, line.split("=", maxsplit=1)) for line in session.open("rt").readlines())
                    yield from self._build_session_record(
                        session.stat().st_mtime, session.name, session, cfg, user_details
                    )

    def _build_session_record(
        self, ts: float, name: float | datetime, source: Path, cfg: dict, user_details: UserDetails
    ) -> PuTTYSessionRecord:
        host, user = parse_host_user(cfg.get("HostName"), cfg.get("UserName"))

        yield PuTTYSessionRecord(
            ts=ts,
            session_name=name,
            protocol=cfg.get("Protocol"),
            host=host,
            user=user,
            port=cfg.get("PortNumber"),
            remote_command=cfg.get("RemoteCommand"),
            port_forward=cfg.get("PortForwardings"),
            manual_ssh_host_keys=cfg.get("SSHManualHostKeys"),
            path=source,
            _target=self.target,
            _user=user_details.user if user_details else None,
        )


def parse_host_user(host: str, user: str) -> tuple[str, str]:
    """Parse host and user from PuTTY hostname component."""
    if "@" in host:
        parsed_user, parsed_host = host.split("@")
        user = user or parsed_user
        host = parsed_host

    return host, user


def construct_public_key(key_type: str, iv: str) -> tuple[str, tuple[str, str, str]]:
    """Returns OpenSSH format public key calculated from PuTTY SshHostKeys format and set of fingerprints.

    PuTTY stores raw public key components instead of OpenSSH-formatted public keys
    or fingerprints. With RSA public keys the exponent and modulus are stored.
    With ECC keys the x and y prime coordinates are stored together with the curve type.

    Currently supports ``ssh-ed25519``, ``ecdsa-sha2-nistp256`` and ``rsa2`` key types.

    NOTE: More key types could be supported in the future.

    Resources:
        - https://github.com/github/putty/blob/master/contrib/kh2reg.py
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
        - https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html
        - https://github.com/mkorthof/reg2kh
    """
    if not HAS_CRYPTO:
        log.warning("Could not reconstruct public key: missing pycryptodome dependency")
        return iv

    if not isinstance(key_type, str) or not isinstance(iv, str):
        raise TypeError("Invalid key_type or iv")

    key = None

    if key_type == "ssh-ed25519":
        x, y = iv.split(",")
        key = ECC.construct(curve="ed25519", point_x=int(x, 16), point_y=int(y, 16))

    if key_type == "ecdsa-sha2-nistp256":
        _, x, y = iv.split(",")
        key = ECC.construct(curve="NIST P-256", point_x=int(x, 16), point_y=int(y, 16))

    if key_type == "rsa2":
        exponent, modulus = iv.split(",")
        key = RSA.construct((int(modulus, 16), int(exponent, 16)))

    if key is None:
        log.warning("Could not reconstruct public key: type %s not implemented", key_type)
        return iv, (None, None, None)

    openssh_public_key = key.public_key().export_key(format="OpenSSH")

    if isinstance(openssh_public_key, bytes):
        # RSA's export_key() returns bytes
        openssh_public_key = openssh_public_key.decode()

    key_part = openssh_public_key.split()[-1]
    fingerprints = calculate_fingerprints(b64decode(key_part))
    return key_part, fingerprints
