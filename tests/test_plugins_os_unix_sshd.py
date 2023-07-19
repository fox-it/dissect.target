from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.sshd import SSHServerPlugin

from ._utils import absolute_path


def test_sshd_config_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem):
    config_file = absolute_path("data/unix/configs/sshd_config")
    fs_unix.map_file(SSHServerPlugin.SSHD_CONFIG_PATH, config_file)

    target_unix_users.add_plugin(SSHServerPlugin)
    results = list(target_unix_users.sshd.config())

    assert len(results) == 1
    assert str(results[0].source) == SSHServerPlugin.SSHD_CONFIG_PATH
    assert results[0].Port == [22, 1234]
    assert results[0].LoginGraceTime == "2m"
    assert results[0].PermitRootLogin == "prohibit-password"
    assert results[0].StrictModes
    assert results[0].MaxAuthTries == 6
    assert not hasattr(results[0], "PubkeyAuthentication")
    assert results[0].AuthorizedKeysFile == ".ssh/authorized_keys"
