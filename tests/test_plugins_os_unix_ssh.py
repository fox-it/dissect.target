import textwrap
from io import BytesIO

from flow.record.fieldtypes import path

from dissect.target.plugins.os.unix.ssh import SSHPlugin


def test_authorized_keys_plugin(target_unix_users, fs_unix):
    authorized_keys_data = """
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw comment
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw long comment with spaces
    command="foo bar" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw
    command="foo bar" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw with a comment
    # Invalid
    ssh-ed25519
    """

    fs_unix.map_file_fh(
        "/root/.ssh/authorized_keys",
        BytesIO(textwrap.dedent(authorized_keys_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.authorized_keys())
    assert len(results) == 5

    assert results[0].keytype == "ssh-ed25519"
    assert results[0].options is None
    assert results[0].comment == ""

    assert results[1].keytype == "ssh-ed25519"
    assert results[1].options is None
    assert results[1].comment == "comment"

    assert results[2].keytype == "ssh-ed25519"
    assert results[2].options is None
    assert results[2].comment == "long comment with spaces"

    assert results[3].keytype == "ssh-ed25519"
    assert results[3].options == 'command="foo bar"'
    assert results[3].comment == ""

    assert results[4].keytype == "ssh-ed25519"
    assert results[4].options == 'command="foo bar"'
    assert results[4].comment == "with a comment"


def test_known_hosts_plugin(target_unix_users, fs_unix):
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

    fs_unix.map_file_fh(
        "/root/.ssh/known_hosts",
        BytesIO(textwrap.dedent(known_hosts_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.known_hosts())
    assert len(results) == 6

    assert results[0].hostname_pattern == "cvs.example.net"
    assert results[0].keytype == "ssh-rsa"
    assert results[0].comment == "comment with spaces"
    assert results[0].marker is None

    assert results[1].hostname_pattern == "192.0.2.10"
    assert results[1].keytype == "ssh-rsa"
    assert results[1].comment == "comment with spaces"
    assert results[1].marker is None

    assert results[2].hostname_pattern == "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM="
    assert results[2].keytype == "ssh-rsa"
    assert results[2].comment == ""
    assert results[2].marker is None

    assert results[3].hostname_pattern == "*"
    assert results[3].keytype == "ssh-rsa"
    assert results[3].comment == ""
    assert results[3].marker == "@revoked"

    assert results[4].hostname_pattern == "*.mydomain.org"
    assert results[4].keytype == "ssh-rsa"
    assert results[4].comment == ""
    assert results[4].marker == "@cert-authority"

    assert results[5].hostname_pattern == "*.mydomain.com"
    assert results[5].keytype == "ssh-rsa"
    assert results[5].comment == ""
    assert results[5].marker == "@cert-authority"


def test_private_keys_plugin_rfc4716_ed25519(target_unix_users, fs_unix):
    private_key_data = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsAAAAJhebt8UXm7f
    FAAAAAtzc2gtZWQyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsA
    AAAECwfJEGqm+M4uYAWj3RMwA/6OcwmM48QT2MTCU5XSZpmdz6oq+IweAoQFMzQ0aJLYXJ
    FkLn3tXMbVZ550wvUKOwAAAAEWxvbmcgY29tbWVudCBoZXJlAQIDBA==
    -----END OPENSSH PRIVATE KEY-----
    """

    public_key_data = "AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw"

    fs_unix.map_file_fh(
        "/etc/ssh/ssh_host_ed25519_key",
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    fs_unix.map_file_fh(
        "/root/.ssh/garbage_file",
        BytesIO(textwrap.dedent("FOO PRIVATE KEY----- BAR").encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.private_keys())
    assert len(results) == 1

    private_key = results[0]
    assert private_key.key_format == "RFC4716"
    assert private_key.key_type == "ssh-ed25519"
    assert private_key.comment == "long comment here"
    assert private_key.public_key == public_key_data
    assert not private_key.encrypted
    assert private_key.source == path.from_posix("/etc/ssh/ssh_host_ed25519_key")


def test_private_keys_plugin_rfc4716_rsa_encrypted(target_unix_users, fs_unix):
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

    fs_unix.map_file_fh(
        "/root/.ssh/id_rsa",
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "RFC4716"
    assert private_key.key_type == "ssh-rsa"
    assert private_key.public_key == public_key_data
    assert private_key.comment == ""
    assert private_key.encrypted
    assert private_key.source == path.from_posix("/root/.ssh/id_rsa")


def test_private_keys_plugin_pem_ecdsa(target_unix_users, fs_unix):
    private_key_data = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIPLzo1QWDkkMxKEG3X8fW7495i5GtVeQhnkpvXMJTZAooAoGCCqGSM49
    AwEHoUQDQgAEn14FkGUBSSX0ocobnqqcWpeSPKgUJDj1sZtXwLTdfPkZ4++J/HiA
    T9q+r/zG2BunHjtTaa0isjJgXWw++3JAzg==
    -----END EC PRIVATE KEY-----"""

    fs_unix.map_file_fh(
        "/root/.ssh/id_ecdsa",
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "PEM"
    assert private_key.key_type == "ecdsa"
    assert private_key.user == "root"
    assert not private_key.encrypted
    assert private_key.source == path.from_posix("/root/.ssh/id_ecdsa")


def test_private_keys_plugin_pkcs8_dsa(target_unix_users, fs_unix):
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

    fs_unix.map_file_fh(
        "/root/.ssh/id_dsa",
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.private_keys())
    private_key = results[0]

    assert len(results) == 1
    assert private_key.key_format == "PKCS8"
    assert private_key.user == "root"
    assert not private_key.encrypted
    assert private_key.source == path.from_posix("/root/.ssh/id_dsa")


def test_public_keys_plugin(target_unix_users, fs_unix):
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

    fs_unix.map_file_fh(
        "/root/.ssh/id_ed25519.pub",
        BytesIO(textwrap.dedent(user_public_key_data).encode()),
    )

    fs_unix.map_file_fh(
        "/etc/ssh/ssh_host_rsa_key.pub",
        BytesIO(textwrap.dedent(host_public_key_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.public_keys())

    assert len(results) == 2

    user_public_key = results[0]
    host_public_key = results[1]

    assert user_public_key.key_type == user_public_key_data.split(" ", 2)[0]
    assert user_public_key.public_key == user_public_key_data.split(" ", 2)[1]
    assert user_public_key.comment == user_public_key_data.split(" ", 2)[2]
    assert user_public_key.source == path.from_posix("/root/.ssh/id_ed25519.pub")

    assert host_public_key.key_type == host_public_key_data.split(" ", 2)[0]
    assert host_public_key.public_key == host_public_key_data.split(" ", 2)[1]
    assert host_public_key.comment == host_public_key_data.split(" ", 2)[2]
    assert host_public_key.source == path.from_posix("/etc/ssh/ssh_host_rsa_key.pub")
