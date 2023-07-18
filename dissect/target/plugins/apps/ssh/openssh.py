import re
from functools import cached_property
from itertools import product
from pathlib import Path
from typing import Iterator

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.ssh import SSHPrivateKey
from dissect.target.plugin import Plugin, export

AuthorizedKeysRecord = TargetRecordDescriptor(
    "application/openssh/authorized_keys",
    [
        ("string", "user"),
        ("string", "keytype"),
        ("string", "public_key"),
        ("string", "comment"),
        ("string", "options"),
        ("uri", "path"),
    ],
)


KnownHostRecord = TargetRecordDescriptor(
    "application/openssh/known_host",
    [
        ("string", "user"),
        ("string", "hostname_pattern"),
        ("string", "keytype"),
        ("string", "public_key"),
        ("string", "comment"),
        ("string", "marker"),
        ("uri", "path"),
    ],
)


PrivateKeyRecord = TargetRecordDescriptor(
    "application/openssh/private_key",
    [
        ("datetime", "mtime_ts"),
        ("string", "user"),
        ("string", "key_format"),
        ("string", "key_type"),
        ("string", "public_key"),
        ("string", "comment"),
        ("boolean", "encrypted"),
        ("path", "source"),
    ],
)

PublicKeyRecord = TargetRecordDescriptor(
    "application/openssh/public_key",
    [
        ("datetime", "mtime_ts"),
        ("string", "user"),
        ("string", "key_type"),
        ("string", "public_key"),
        ("string", "comment"),
        ("path", "source"),
    ],
)


class SSHPlugin(Plugin):
    __namespace__ = "ssh"

    SSHD_DIRECTORIES = ["/sysvol/ProgramData/ssh", "/etc/ssh"]

    def check_compatible(self):
        sshd_user_dirs = any(
            user_details.home_path.joinpath(".ssh").exists()
            for user_details in self.target.user_details.all_with_home()
        )
        return sshd_user_dirs or self.sshd_directory.exists()

    @cached_property
    def sshd_directory(self) -> TargetPath:
        for sshd in self.SSHD_DIRECTORIES:
            if (target_path := self.target.fs.path(sshd)).exists():
                return target_path

        # A default, so there is no need to check for None
        return self.target.fs.path("/etc/ssh/")

    def ssh_directory_globs(self, glob_user: str, glob_sshd: str) -> list[tuple[str, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            yield from product([user_details.user.name], user_details.home_path.glob(f".ssh/{glob_user}"))

        yield from product([None], self.sshd_directory.glob(glob_sshd))

    @export(record=AuthorizedKeysRecord)
    def authorized_keys(self) -> Iterator[AuthorizedKeysRecord]:
        """Yields the content of the authorized_keys files on a target for each user."""
        for user_name, authorized_keys_file in self.ssh_directory_globs(
            "authorized_keys*", "administrator_authorized_keys"
        ):
            for line in authorized_keys_file.open("rt"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    options, keytype, public_key, comment = parse_ssh_key(line)
                except ValueError:
                    continue

                yield AuthorizedKeysRecord(
                    user=user_name,
                    keytype=keytype,
                    public_key=public_key,
                    comment=comment,
                    options=options,
                    path=str(authorized_keys_file),
                    _target=self.target,
                )

    @export(record=KnownHostRecord)
    def known_hosts(self) -> Iterator[KnownHostRecord]:
        """Yields the content of the known_hosts files on a target for each user."""

        for user_name, known_hosts_file in self.ssh_directory_globs("known_hosts*", "ssh_known_hosts"):
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
                        user=user_name,
                        hostname_pattern=hostname,
                        keytype=keytype,
                        public_key=public_key,
                        comment=comment,
                        marker=marker,
                        path=str(known_hosts_file),
                        _target=self.target,
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
                user=user,
                key_format=private_key.format,
                key_type=private_key.key_type,
                public_key=private_key.public_key,
                comment=private_key.comment,
                encrypted=private_key.is_encrypted,
                source=file_path,
                _target=self.target,
            )

    @export(record=PublicKeyRecord)
    def public_keys(self) -> Iterator[PublicKeyRecord]:
        """Yields all SSH public keys from all user home directories and the ssh daemon configuration directory."""

        for user, file_path in self.ssh_directory_globs("*.pub", "*.pub"):
            if not file_path.is_file():
                continue

            key_type, public_key, comment = parse_ssh_public_key_file(file_path)

            yield PublicKeyRecord(
                mtime_ts=file_path.stat().st_mtime,
                user=user,
                key_type=key_type,
                public_key=public_key,
                comment=comment,
                source=file_path,
                _target=self.target,
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
