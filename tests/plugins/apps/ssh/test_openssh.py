from __future__ import annotations

import base64
import textwrap
from enum import Enum, auto
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.ssh.openssh import (
    OpenSSHPlugin,
    calculate_fingerprints,
)

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture(
    params=[
        ("target_unix_users", "fs_unix"),
        ("target_win_users", "fs_win"),
    ],
    ids=["target_unix", "target_windows"],
)
def target_and_filesystem(request: pytest.FixtureRequest) -> tuple[Target, VirtualFilesystem]:
    target = request.getfixturevalue(request.param[0])
    filesystem = request.getfixturevalue(request.param[1])
    return target, filesystem


class TargetDir(Enum):
    HOME = auto()
    SSHD = auto()


class Alternatives:
    user_name: str
    home_dir: str
    sshd_dir: str
    os_type: str
    separator: str
    label: str

    @classmethod
    def from_target(cls, target: Target) -> Self:
        alternative = cls()
        alternative.os_type = target._os.os
        alternative.separator = "/"
        alternative.label = "NO_LABEL"

        if alternative.os_type == "windows":
            alternative.separator = target.fs.alt_separator
            alternative.home_dir = "C:\\Users\\John"
            alternative.sshd_dir = "C:\\ProgramData\\ssh"
            alternative.user_name = "John"
            alternative.label = "C:\\"
        else:
            alternative.home_dir = "/root"
            alternative.sshd_dir = "/etc/ssh"
            alternative.user_name = "root"

        return alternative

    def mapping_path(self, file_name: str, target_dir: TargetDir) -> str:
        return self.filesystem_path(file_name, target_dir).strip(self.label)

    def filesystem_path(self, file_name: str, target_dir: TargetDir) -> str:
        mapping = {TargetDir.HOME: self.home_dir, TargetDir.SSHD: self.sshd_dir}
        return self.separator.join([mapping.get(target_dir), *file_name.split("/")])


def test_authorized_keys_plugin(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    authorized_keys_data = """
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw comment
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw long comment with spaces
    command="foo bar" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw
    command="foo bar" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw with a comment
    # Invalid
    ssh-ed25519
    """

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/authorized_keys", target_dir=TargetDir.HOME),
        BytesIO(textwrap.dedent(authorized_keys_data).encode()),
    )
    fs.map_file_fh(
        target_system.mapping_path("administrator_authorized_keys", target_dir=TargetDir.SSHD),
        BytesIO(textwrap.dedent(authorized_keys_data).encode()),
    )

    plugin = OpenSSHPlugin(target)

    results = list(plugin.authorized_keys())
    assert len(results) == 10

    assert results[0].key_type == "ssh-ed25519"
    assert results[0].options is None
    assert results[0].comment == ""

    assert results[1].key_type == "ssh-ed25519"
    assert results[1].options is None
    assert results[1].comment == "comment"

    assert results[2].key_type == "ssh-ed25519"
    assert results[2].options is None
    assert results[2].comment == "long comment with spaces"

    assert results[3].key_type == "ssh-ed25519"
    assert results[3].options == 'command="foo bar"'
    assert results[3].comment == ""

    assert results[4].key_type == "ssh-ed25519"
    assert results[4].options == 'command="foo bar"'
    assert results[4].comment == "with a comment"


def test_known_hosts_plugin(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem

    known_hosts_data = """
    # Comments allowed at start of line
    cvs.example.net,192.0.2.10 ssh-rsa AAAA1234.....= comment with spaces
    # A hashed hostname
    |1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-rsa AAAA1234.....=
    # A revoked key
    @revoked * ssh-rsa AAAAB5W...
    # A CA key, accepted for any host in *.mydomain.com or *.mydomain.org
    @cert-authority *.mydomain.org,*.mydomain.com ssh-rsa AAAAB5W...
    """

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/known_hosts", target_dir=TargetDir.HOME),
        BytesIO(textwrap.dedent(known_hosts_data).encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.known_hosts())
    assert len(results) == 6

    assert results[0].host == "cvs.example.net"
    assert results[0].key_type == "ssh-rsa"
    assert results[0].comment == "comment with spaces"
    assert results[0].marker is None

    assert results[1].host == "192.0.2.10"
    assert results[1].key_type == "ssh-rsa"
    assert results[1].comment == "comment with spaces"
    assert results[1].marker is None

    assert results[2].host == "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM="
    assert results[2].key_type == "ssh-rsa"
    assert results[2].comment == ""
    assert results[2].marker is None

    assert results[3].host == "*"
    assert results[3].key_type == "ssh-rsa"
    assert results[3].comment == ""
    assert results[3].marker == "@revoked"

    assert results[4].host == "*.mydomain.org"
    assert results[4].key_type == "ssh-rsa"
    assert results[4].comment == ""
    assert results[4].marker == "@cert-authority"

    assert results[5].host == "*.mydomain.com"
    assert results[5].key_type == "ssh-rsa"
    assert results[5].comment == ""
    assert results[5].marker == "@cert-authority"
    assert results[5].username == target_system.user_name


def test_private_keys_plugin_rfc4716_ed25519(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    private_key_data = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsAAAAJhebt8UXm7f
    FAAAAAtzc2gtZWQyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsA
    AAAECwfJEGqm+M4uYAWj3RMwA/6OcwmM48QT2MTCU5XSZpmdz6oq+IweAoQFMzQ0aJLYXJ
    FkLn3tXMbVZ550wvUKOwAAAAEWxvbmcgY29tbWVudCBoZXJlAQIDBA==
    -----END OPENSSH PRIVATE KEY-----
    """

    target_system = Alternatives.from_target(target)

    public_key_data = "AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw"

    fs.map_file_fh(
        target_system.mapping_path("ssh_host_ed25519_key", TargetDir.SSHD),
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    fs.map_file_fh(
        target_system.mapping_path(".ssh/garbage_file", TargetDir.HOME),
        BytesIO(textwrap.dedent("FOO PRIVATE KEY----- BAR").encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.private_keys())
    assert len(results) == 1

    private_key = results[0]
    assert private_key.key_format == "RFC4716"
    assert private_key.key_type == "ssh-ed25519"
    assert private_key.comment == "long comment here"
    assert private_key.public_key == public_key_data
    assert not private_key.encrypted
    assert str(private_key.path).replace("\\", "/") == target_system.filesystem_path(
        "ssh_host_ed25519_key", TargetDir.SSHD
    ).replace(target_system.label, "\\sysvol\\").replace("\\", "/")


def test_private_keys_plugin_rfc4716_rsa_encrypted(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    # Generated using password "password".
    private_key_data = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    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
    vp9YaQ==
    -----END OPENSSH PRIVATE KEY-----"""

    public_key_data = (
        "AAAAB3NzaC1yc2EAAAADAQABAAABgQDBz7gMDWRd6VMfxUEXLwYVfk4Tt7C9luYtoFcU6GcdUx8lhhZX4tBCTth4Abm1EDyBX+OFt0UO9tHaYI"
        "dctzn0tAaEIoV6vpGEOx3NyqwG63DFruuJVYaQKfnMqADMBTjKGXbSKMosJA9bLT+mR8oGObnadUfi3/n4QmmKtyXt+THxwDvM4qTplEsgss91"
        "2LtOVGBfUj2a1HLljTlydz/0JlC20OnG516XLq7aM/TRXvYWxa5jWRwlsP795SA2Zd9aeAk6d5PvYRIcdPnmW9DwN3LXFq/7JNMHVpB/reHlBb"
        "TUOGbbKP8Ba71fgcYoSPDaXtkUsjaHjEFpBpwjROcJKUxiCPcrHyBxaKpI8QaeJWXyBaIUWJbsBFy65F8EOPZYR95ZI4yQvmw2lp75g7DwNCp7"
        "Xu3jljaeIzR2LDLk282x0A++Di6tG+IzVvMOcgEJIzykofOEXMJt0oVhnvIr9y5VWl/G8X1e20GqjiImLSGKgvZnzPx93RmjHXfOQk8="
    )

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/id_rsa", TargetDir.HOME),
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "RFC4716"
    assert private_key.key_type == "ssh-rsa"
    assert private_key.public_key == public_key_data
    assert private_key.comment == ""
    assert private_key.encrypted
    assert str(private_key.path).replace("\\", "/") == target_system.filesystem_path(
        ".ssh/id_rsa", TargetDir.HOME
    ).replace("\\", "/")


def test_private_keys_plugin_pem_ecdsa(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    private_key_data = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIPLzo1QWDkkMxKEG3X8fW7495i5GtVeQhnkpvXMJTZAooAoGCCqGSM49
    AwEHoUQDQgAEn14FkGUBSSX0ocobnqqcWpeSPKgUJDj1sZtXwLTdfPkZ4++J/HiA
    T9q+r/zG2BunHjtTaa0isjJgXWw++3JAzg==
    -----END EC PRIVATE KEY-----"""

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/id_ecdsa", TargetDir.HOME),
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "PEM"
    assert private_key.key_type == "ecdsa"
    assert private_key.username == target_system.user_name
    assert not private_key.encrypted
    assert str(private_key.path).replace("\\", "/") == target_system.filesystem_path(
        ".ssh/id_ecdsa", TargetDir.HOME
    ).replace("\\", "/")


def test_private_keys_plugin_pkcs8_dsa(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    private_key_data = """
    -----BEGIN PRIVATE KEY-----
    MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAP78NtXw6e2YgD3caU3LbY3fxCtz
    W9R+AF4s3nlbAKCx9lVtnSnEE+sbByfinV3iCmlf8muU0AS/7E9aFMqkDM5sG+cK
    ttJ689Ef/RmrZP2QE8YyZgKLGiK2HVmPVvBEhfWA/Pge45zuPoEAf33czqC6LF0k
    Kq0842BuGsx4iYx3AhUAph7ywYR16EZyIKpQvVZjEoqgp3sCgYBbjazw8sAjAEFX
    xpPl58Iy52wMb53/8tpOUBU1Nn4jPUmgzszrd1cpt4TGtqHasi2uWWyyPmYQe/i2
    YfMY4MAosSA9ZaqIi4Dkd3L+7rIS4zMy7LcTuhaex0n4V0qYBjRZJFXV9iqBN83l
    Klm96maH1SL9x5+GZR6mAjYyfZ+4sgQWAhROqDuRIc5ilMqjV0pG2spo7HVuwg==
    -----END PRIVATE KEY-----"""

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/id_dsa", TargetDir.HOME),
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "PKCS8"
    assert private_key.username == target_system.user_name
    assert not private_key.encrypted
    assert str(private_key.path).replace("\\", "/") == target_system.filesystem_path(
        ".ssh/id_dsa", TargetDir.HOME
    ).replace("\\", "/")


def test_public_keys_plugin(target_and_filesystem: tuple[Target, VirtualFilesystem]) -> None:
    target, fs = target_and_filesystem
    user_public_key_data = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw long comment here"
    )

    host_public_key_data = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDUZo/RgdRqnitmlWcD7dXcFuIr5528xaJ65exm7FCqrQDMsdlV8naH6bxSmmA0eLUS/YUFwr"
        "YRdkC925rRE37kNfleDycbm6j5QCAT6eZZgftUEUicpcqA52PYzzzGi1g56n3DkkxkoKA5XZkTilHEZLLV1zgUR9GzzvvT8VpgwyNCm9qxfsBC"
        "tywrg6MCqBY/0ssh156pDVmHHr7eWUBkdlj4I16YHLQRPblt9jnUx7S37T/ZRFTRtupePcGCEU9X4D5fWmRfJMIyNtd6LJ9wAXh/h2D+tKW6Th"
        "A1rFDrnYQqcUR2zjSkfSCyYGkt9CnoYhpFdEv3fYRuNCUM8hKa01mGtfy4Vnwh5TL6M4uKhdUR4DZ5CLesciTEz4zbmeXhY5vIij0vsXaP047E"
        "QhwLXXTyyqZ+Pt5oCfrFBtDMtv9NxBMsZ1XGYuSlrc1mqasFBeg0SpIADsJ5DMaWUkkuoeF414PYd8Emu+B6In3h6aHEsP7ELkr9C+qImzIly4"
        "s= comment"
    )

    target_system = Alternatives.from_target(target)

    fs.map_file_fh(
        target_system.mapping_path(".ssh/id_ed25519.pub", TargetDir.HOME),
        BytesIO(textwrap.dedent(user_public_key_data).encode()),
    )

    fs.map_file_fh(
        target_system.mapping_path("ssh_host_rsa_key.pub", TargetDir.SSHD),
        BytesIO(textwrap.dedent(host_public_key_data).encode()),
    )

    target.add_plugin(OpenSSHPlugin)

    results = list(target.openssh.public_keys())

    assert len(results) == 2

    user_public_key = results[0]
    host_public_key = results[1]

    assert user_public_key.key_type == user_public_key_data.split(" ", 2)[0]
    assert user_public_key.public_key == user_public_key_data.split(" ", 2)[1]
    assert user_public_key.comment == user_public_key_data.split(" ", 2)[2]
    assert user_public_key.fingerprint.md5 == "1f3d475966231eeb5455c8485dd030e4"
    assert user_public_key.fingerprint.sha1 == "e39242ca1d74bea99285b212e908e18cc67e4dec"
    assert user_public_key.fingerprint.sha256 == "7b77007b0b51a86ced6b5fe25639092484c4c39cf76b283ef65fdf49a00f44d2"
    assert str(user_public_key.path).replace("\\", "/") == target_system.filesystem_path(
        ".ssh/id_ed25519.pub", TargetDir.HOME
    ).replace("\\", "/")

    assert host_public_key.key_type == host_public_key_data.split(" ", 2)[0]
    assert host_public_key.public_key == host_public_key_data.split(" ", 2)[1]
    assert host_public_key.comment == host_public_key_data.split(" ", 2)[2]
    assert host_public_key.fingerprint.md5 == "a3f2ebfa8d16efd321015e1618fd281b"
    assert host_public_key.fingerprint.sha1 == "f6656cc642fb08f53a1df77d0acff9852a649989"
    assert host_public_key.fingerprint.sha256 == "8c7023d563c763fcf5104332d7cf51c978c5ba1dd9f5cbd341edd32dfcbef3ef"
    assert str(host_public_key.path).replace("\\", "/") == target_system.filesystem_path(
        "ssh_host_rsa_key.pub", TargetDir.SSHD
    ).replace(target_system.label, "\\sysvol\\").replace("\\", "/")


def test_calculate_fingerprints() -> None:
    ed25519_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw long comment here"

    assert calculate_fingerprints(base64.b64decode(ed25519_pub.split(" ")[1])) == (
        "1f3d475966231eeb5455c8485dd030e4",
        "e39242ca1d74bea99285b212e908e18cc67e4dec",
        "7b77007b0b51a86ced6b5fe25639092484c4c39cf76b283ef65fdf49a00f44d2",
    )

    assert calculate_fingerprints(base64.b64decode(ed25519_pub.split(" ")[1]), ssh_keygen_format=True) == (
        "1f3d475966231eeb5455c8485dd030e4",
        "45JCyh10vqmShbIS6QjhjMZ+Tew",
        "e3cAewtRqGzta1/iVjkJJITEw5z3ayg+9l/fSaAPRNI",
    )
