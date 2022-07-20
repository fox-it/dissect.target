import re
import subprocess

from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import TargetRecordDescriptor


AuthorizedKeysRecord = TargetRecordDescriptor(
    "unix/ssh/authorized_keys",
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
    "unix/ssh/known_host",
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
    "unix/ssh/private_key",
    [
        ("string", "user"),
        ("string", "keytype"),
        ("string", "public_key"),
        ("string", "comment"),
        ("boolean", "encrypted"),
        ("uri", "path"),
    ],
)


class SSHPlugin(Plugin):
    __namespace__ = "ssh"

    def check_compatible(self):
        return len(list(self.target.users())) > 0 and self.target.os != "windows"

    @export(record=AuthorizedKeysRecord)
    def authorized_keys(self):
        """Yields the content of the authorized_keys files on a Unix target per user."""
        for user_details in self.target.user_details.all_with_home():
            for authorized_keys_file in user_details.home_path.glob(".ssh/authorized_keys*"):
                for line in authorized_keys_file.open("rt"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    try:
                        options, keytype, public_key, comment = parse_ssh_key(line)
                    except ValueError:
                        continue

                    yield AuthorizedKeysRecord(
                        user=user_details.user.name,
                        keytype=keytype,
                        public_key=public_key,
                        comment=comment,
                        options=options,
                        path=str(authorized_keys_file),
                        _target=self.target,
                    )

    @export(record=KnownHostRecord)
    def known_hosts(self):
        """Yields the content of the known_hosts files on a Unix target per user."""
        known_hosts_files = []
        for user_details in self.target.user_details.all_with_home():
            if user_details.home_path == "/dev/null":
                continue

            known_hosts_files.extend(
                [(user_details, path) for path in user_details.home_path.glob(".ssh/known_hosts*")]
            )

        etc_known_hosts = self.target.fs.path("/etc/sshd/ssh_known_hosts")
        if etc_known_hosts.exists():
            known_hosts_files.append((None, etc_known_hosts))

        for user_details, known_hosts_file in known_hosts_files:
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
                        user=user_details.user.name if user_details else None,
                        hostname_pattern=hostname,
                        keytype=keytype,
                        public_key=public_key,
                        comment=comment,
                        marker=marker,
                        path=str(known_hosts_file),
                        _target=self.target,
                    )

    @export(record=PrivateKeyRecord)
    def private_keys(self):
        for user_details in self.target.user_details.all_with_home():
            for file_path in user_details.home_path.glob(".ssh/*"):
                file_buf = file_path.read_bytes()

                if b"PRIVATE KEY-----" not in file_buf:
                    continue

                encrypted = b"ENCRYPTED" in file_buf

                public_key_data = None
                public_key_path = file_path.with_suffix(".pub")
                if public_key_path.exists():
                    public_key_data = public_key_path.read_text()
                elif not encrypted:
                    try:
                        output = subprocess.run(
                            ["ssh-keygen", "-y", "-f", "/dev/stdin"], input=file_buf, stdout=subprocess.PIPE
                        )
                        public_key_data = output.stdout.decode("utf-8").strip()
                    except Exception:
                        self.target.log.exception("Failed to generate public key from private key %s", file_path)

                _, keytype, public_key, comment = None, None, None, None
                if public_key_data:
                    _, keytype, public_key, comment = parse_ssh_key(public_key_data)

                yield PrivateKeyRecord(
                    user=user_details.user.name,
                    keytype=keytype,
                    public_key=public_key,
                    comment=comment,
                    encrypted=encrypted,
                    path=str(file_path),
                    _target=self.target,
                )


def parse_ssh_key(key_string):
    parts = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', key_string)

    options = None
    if not key_string.startswith(("sk-", "ssh-", "ecdsa-")):
        options = parts.pop(0)

    keytype, public_key = parts[:2]

    # We strip whitespace to make parsing a bit safer, but this means we also strip "empty" comments
    # An empty comment is technically "", so return that instead of None
    comment = " ".join(parts[2:]) if len(parts) > 2 else ""

    return options, keytype, public_key, comment


def parse_known_host(known_host_string):
    parts = known_host_string.split()

    marker = None
    if parts[0].startswith("@"):
        marker = parts.pop(0)

    hostnames, keytype, public_key = parts[:3]

    # We strip whitespace to make parsing a bit safer, but this means we also strip "empty" comments
    # An empty comment is technically "", so return that instead of None
    comment = " ".join(parts[3:]) if len(parts) > 3 else ""

    return marker, hostnames.split(","), keytype, public_key, comment
