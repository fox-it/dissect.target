from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.services import ServicesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_services(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    systemd_service_1 = absolute_path("_data/plugins/os/unix/services/systemd.service")
    systemd_service_2 = absolute_path("_data/plugins/os/unix/services/systemd2.service")
    initd_service_1 = absolute_path("_data/plugins/os/unix/services/initd.sh")
    fs_unix.map_file("/lib/systemd/system/example.service", systemd_service_1)
    fs_unix.symlink("/dev/null", "/lib/systemd/system/broken_sym_example.service")
    fs_unix.map_file("/usr/lib/systemd/system/example2.service", systemd_service_2)
    fs_unix.map_file("/etc/init.d/example", initd_service_1)
    target_unix_users.add_plugin(ServicesPlugin)

    results = list(target_unix_users.services())
    assert len(results) == 4

    result_0 = results[0]
    assert result_0.name == "example.service"
    expected_config = {
        "Unit_Description": "an example systemd service",
        "Unit_After": "foobar.service",
        "Unit_Requires": "foo.service bar.service",
        "Service_Type": "simple",
        "Service_ExecStart": "/usr/sbin/simple-command --key value",
        "Service_SyslogIdentifier": None,
        "Service_TimeoutStopSec": "5",
        "Install_WantedBy": "multi-user.target",
        "Install_Alias": "example.service",
    }
    for key, value in expected_config.items():
        assert getattr(result_0, key) == value

    assert str(result_0.source) == "/lib/systemd/system/example.service"

    assert results[1].name == "broken_sym_example.service"
    assert str(results[1].source) == "/lib/systemd/system/broken_sym_example.service"

    result_2 = results[2]
    assert result_2.name == "example2.service"
    expected_config_2 = {
        "Unit_Description": "an example systemd service",
        "Unit_After": "foobar.service",
        "Unit_Requires": "foo.service bar.service",
        "Service_Type": "simple",
        "Service_ExecStart": (
            "/bin/bash -c 'exec /usr/bin/example param1 --param2=value2 -P3value3 -param4 value4; exit 0'"
        ),
        "Service_SyslogIdentifier": "example-service",
        "Service_TimeoutStopSec": "5",
        "Install_WantedBy": "multi-user.target",
        "Install_Alias": "example.service",
    }

    for key, value in expected_config_2.items():
        assert getattr(result_2, key) == value
    assert str(result_2.source) == "/usr/lib/systemd/system/example2.service"

    assert results[3].name == "example"
    assert str(results[3].source) == "/etc/init.d/example"
