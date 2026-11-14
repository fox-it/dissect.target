from __future__ import annotations

import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.ssh.opensshd import OpenSshdConfigRecord, SSHServerPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_sshd_config_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    config_file = absolute_path("_data/plugins/apps/ssh/opensshd/sshd_config")
    plugin = SSHServerPlugin(target_unix_users)
    fs_unix.map_file(str(plugin.sshd_config_path), config_file)

    target_unix_users.add_plugin(SSHServerPlugin)
    results = list(target_unix_users.opensshd.config())

    assert len(results) == 1
    result = results[0]

    assert str(result.source) == str(plugin.sshd_config_path)
    assert result.Port == [22]
    assert result.LoginGraceTime == "2m"
    assert result.PermitRootLogin == "prohibit-password"
    assert result.StrictModes
    assert result.MaxAuthTries == 6
    assert not hasattr(result, "PubkeyAuthentication")
    assert result.AuthorizedKeysFile == ".ssh/authorized_keys"


def test_sshd_config_plugin_multiple_definitions(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    config = """
    Port 22
    Port 1234
    ListenAddress 1.2.3.4
    ListenAddress 9.8.7.6
    """

    plugin = SSHServerPlugin(target_unix_users)
    fs_unix.map_file_fh(
        str(plugin.sshd_config_path),
        BytesIO(textwrap.dedent(config).encode()),
    )

    target_unix_users.add_plugin(SSHServerPlugin)
    results = list(target_unix_users.opensshd.config())

    assert len(results) == 1
    result = results[0]

    assert str(result.source) == str(plugin.sshd_config_path)
    assert result.Port == [22, 1234]
    assert result.ListenAddress == ["1.2.3.4", "9.8.7.6"]


def test_sshd_config_plugin_called_twice(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Parsing a config must not add its fields to ``OpenSshdConfigRecord``, or the next config gets them twice."""
    plugin = SSHServerPlugin(target_unix_users)
    fs_unix.map_file_fh(str(plugin.sshd_config_path), BytesIO(b"Port 22\nPort 1234\n"))
    target_unix_users.add_plugin(SSHServerPlugin)

    record_fields = list(OpenSshdConfigRecord.target_fields)
    first = next(target_unix_users.opensshd.config())
    second = next(target_unix_users.opensshd.config())

    assert OpenSshdConfigRecord.target_fields == record_fields
    for result in (first, second):
        field_names = [name for _, name in result._desc.get_field_tuples()]
        assert field_names.count("Port") == 1
        assert result.Port == [22, 1234]
