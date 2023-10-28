import re
from itertools import product
from pathlib import Path
from typing import Iterator

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.ssh import SSHPrivateKey
from dissect.target.plugin import Plugin, export

OpenSSHUserRecordDescriptor = create_extended_descriptor([UserRecordDescriptorExtension])

COMMON_ELLEMENTS = [
    ("string", "key_type"),
    ("string", "comment"),
    ("path", "path"),
]

AuthorizedKeysRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/authorized_keys",
    [
        *COMMON_ELLEMENTS,
        ("string", "public_key"),
        ("string", "options"),
    ],
)


KnownHostRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/known_host",
    [
        *COMMON_ELLEMENTS,
        ("string", "hostname_pattern"),
        ("string", "public_key"),
        ("string", "marker"),
    ],
)


PrivateKeyRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/private_key",
    [
        *COMMON_ELLEMENTS,
        ("datetime", "mtime_ts"),
        ("string", "key_format"),
        ("string", "public_key"),
        ("boolean", "encrypted"),
    ],
)

PublicKeyRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/public_key",
    [
        *COMMON_ELLEMENTS,
        ("datetime", "mtime_ts"),
        ("string", "public_key"),
    ],
)


def find_sshd_directory(target: Target) -> TargetPath:
    SSHD_DIRECTORIES = ["/sysvol/ProgramData/ssh", "/etc/ssh"]

    for sshd in SSHD_DIRECTORIES:
        if (target_path := target.fs.path(sshd)).exists():
            return target_path

    # A default, so there is no need to check for None
    return target.fs.path("/etc/ssh/")


class OpenSSHPlugin(Plugin):
    __namespace__ = "ssh"

    SSHD_DIRECTORIES = ["/sysvol/ProgramData/ssh", "/etc/ssh"]

    def __init__(self, target: Target):
        super().__init__(target)
        self.sshd_directory = find_sshd_directory(target)

    def check_compatible(self) -> None:
        ssh_user_dirs = any(
            user_details.home_path.joinpath(".ssh").exists()
            for user_details in self.target.user_details.all_with_home()
        )
        if not ssh_user_dirs and not self.sshd_directory.exists():
            raise UnsupportedPluginError("No OpenSSH directories found")

    def ssh_directory_globs(self, glob_user: str, glob_sshd: str) -> list[tuple[str, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            yield from product([user_details.user], user_details.home_path.glob(f".ssh/{glob_user}"))

        yield from product([None], self.sshd_directory.glob(glob_sshd))

    @export(record=AuthorizedKeysRecord)
    def authorized_keys(self) -> Iterator[AuthorizedKeysRecord]:
        """Yields the content of the authorized_keys files on a target for each user."""
        for user, authorized_keys_file in self.ssh_directory_globs("authorized_keys*", "administrator_authorized_keys"):
            for line in authorized_keys_file.open("rt"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    options, keytype, public_key, comment = parse_ssh_key(line)
                except ValueError:
                    continue

                yield AuthorizedKeysRecord(
                    key_type=keytype,
                    public_key=public_key,
                    comment=comment,
                    options=options,
                    path=authorized_keys_file,
                    _target=self.target,
                    _user=user,
                )

    @export(record=KnownHostRecord)
    def known_hosts(self) -> Iterator[KnownHostRecord]:
        """Yields the content of the known_hosts files on a target for each user."""

        for user, known_hosts_file in self.ssh_directory_globs("known_hosts*", "ssh_known_hosts"):
            for line in known_hosts_file.open("rt"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    marker, hostnames, keytype, public_key, comment = parse_known_host(line)
                except ValueError:
                    continue

                for hostname in hostnames:
                    yield KnownHostRecord(
                        hostname_pattern=hostname,
                        key_type=keytype,
                        public_key=public_key,
                        comment=comment,
                        marker=marker,
                        path=known_hosts_file,
                        _target=self.target,
                        _user=user,
                    )

    @export(record=PrivateKeyRecord)
    def private_keys(self) -> Iterator[PrivateKeyRecord]:
        """Yields OpenSSH private keys on a target for each user."""

        for user, file_path in self.ssh_directory_globs("*", "*"):
            if not file_path.is_file():
                continue

            buffer = file_path.read_bytes().strip()
            if b"PRIVATE KEY-----" not in buffer:
                continue

            try:
                private_key = SSHPrivateKey(buffer)
            except ValueError as e:
                self.target.log.warning("Failed to parse SSH private key: %s", file_path)
                self.target.log.debug("", exc_info=e)
                continue

            yield PrivateKeyRecord(
                mtime_ts=file_path.stat().st_mtime,
                key_format=private_key.format,
                key_type=private_key.key_type,
                public_key=private_key.public_key,
                comment=private_key.comment,
                encrypted=private_key.is_encrypted,
                path=file_path,
                _target=self.target,
                _user=user,
            )

    @export(record=PublicKeyRecord)
    def public_keys(self) -> Iterator[PublicKeyRecord]:
        """Yields all OpenSSH public keys from all user home directories and the OpenSSH daemon directory."""

        for user, file_path in self.ssh_directory_globs("*.pub", "*.pub"):
            if not file_path.is_file():
                continue

            key_type, public_key, comment = parse_ssh_public_key_file(file_path)

            yield PublicKeyRecord(
                mtime_ts=file_path.stat().st_mtime,
                key_type=key_type,
                public_key=public_key,
                comment=comment,
                path=file_path,
                _target=self.target,
                _user=user,
            )


def parse_ssh_public_key_file(path: Path) -> tuple[str, str, str]:
    _, key_type, public_key, comment = parse_ssh_key(path.read_text().strip())
    return key_type, public_key, comment


def parse_ssh_key(key_string: str) -> tuple[str, str, str, str]:
    parts = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', key_string)

    options = None
    if not key_string.startswith(("sk-", "ssh-", "ecdsa-")):
        options = parts.pop(0)

    keytype, public_key = parts[:2]

    # We strip whitespace to make parsing a bit safer, but this means we also strip "empty" comments
    # An empty comment is technically "", so return that instead of None
    comment = " ".join(parts[2:]) if len(parts) > 2 else ""

    return options, keytype, public_key, comment


def parse_known_host(known_host_string: str) -> tuple[str, list, str, str, str]:
    parts = known_host_string.split()

    marker = None
    if parts[0].startswith("@"):
        marker = parts.pop(0)

    hostnames, keytype, public_key = parts[:3]

    # We strip whitespace to make parsing a bit safer, but this means we also strip "empty" comments
    # An empty comment is technically "", so return that instead of None
    comment = " ".join(parts[3:]) if len(parts) > 3 else ""

    return marker, hostnames.split(","), keytype, public_key, comment
