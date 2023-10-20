from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.ssh.sshd import SSHServerPlugin

from ._utils import absolute_path


def test_sshd_config_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem):
    config_file = absolute_path("data/plugins/apps/sshd_config")
    plugin = SSHServerPlugin(target_unix_users)
    fs_unix.map_file(str(plugin.sshd_config_path), config_file)

    target_unix_users.add_plugin(SSHServerPlugin)
    results = list(target_unix_users.sshd.config())

    assert len(results) == 1
    result = results[0]

    assert str(result.source) == str(plugin.sshd_config_path)
    assert result.Port == [22, 1234]
    assert result.LoginGraceTime == "2m"
    assert result.PermitRootLogin == "prohibit-password"
    assert result.StrictModes
    assert result.MaxAuthTries == 6
    assert not hasattr(result, "PubkeyAuthentication")
    assert result.AuthorizedKeysFile == ".ssh/authorized_keys"