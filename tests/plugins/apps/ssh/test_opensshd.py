from __future__ import annotations

import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.ssh.opensshd import SSHServerPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_sshd_config_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:

    config_file = absolute_path("_data/plugins/apps/ssh/opensshd/sshd_config")
    fs_unix.map_file("/etc/ssh/sshd_config", config_file)
    plugin = SSHServerPlugin(target_unix_users)
    

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

    
    fs_unix.map_file_fh(
        "/etc/ssh/sshd_config",
        BytesIO(textwrap.dedent(config).encode()),
    )
    plugin = SSHServerPlugin(target_unix_users)

    target_unix_users.add_plugin(SSHServerPlugin)
    results = list(target_unix_users.opensshd.config())

    assert len(results) == 1
    result = results[0]

    assert str(result.source) == str(plugin.sshd_config_path)
    assert result.Port == [22, 1234]
    assert result.ListenAddress == ["1.2.3.4", "9.8.7.6"]
