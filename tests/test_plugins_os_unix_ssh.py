import textwrap
from io import BytesIO

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


def test_private_keys_plugin(target_unix_users, fs_unix):
    private_key_data = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsAAAAJhebt8UXm7f
    FAAAAAtzc2gtZWQyNTUxOQAAACDc+qKviMHgKEBTM0NGiS2FyRZC597VzG1WeedML1CjsA
    AAAECwfJEGqm+M4uYAWj3RMwA/6OcwmM48QT2MTCU5XSZpmdz6oq+IweAoQFMzQ0aJLYXJ
    FkLn3tXMbVZ550wvUKOwAAAAEWxvbmcgY29tbWVudCBoZXJlAQIDBA==
    -----END OPENSSH PRIVATE KEY-----
    """
    public_key_data = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINz6oq+IweAoQFMzQ0aJLYXJFkLn3tXMbVZ550wvUKOw long comment here"
    )

    fs_unix.map_file_fh(
        "/root/.ssh/id_ed25519",
        BytesIO(textwrap.dedent(private_key_data).encode()),
    )
    fs_unix.map_file_fh(
        "/root/.ssh/id_ed25519.pub",
        BytesIO(textwrap.dedent(public_key_data).encode()),
    )

    target_unix_users.add_plugin(SSHPlugin)

    results = list(target_unix_users.ssh.private_keys())
    assert len(results) == 1

    assert results[0].keytype == "ssh-ed25519"
    assert results[0].comment == "long comment here"
    assert not results[0].encrypted
