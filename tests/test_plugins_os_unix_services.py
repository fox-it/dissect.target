from dissect.target.plugins.os.unix.services import ServicesPlugin

from ._utils import absolute_path


def test_unix_services(target_unix_users, fs_unix):
    systemd_service_1 = absolute_path("data/plugins/os/unix/services/systemd.service")
    systemd_service_2 = absolute_path("data/plugins/os/unix/services/systemd2.service")
    initd_service_1 = absolute_path("data/plugins/os/unix/services/initd.sh")
    fs_unix.map_file("/lib/systemd/system/example.service", systemd_service_1)
    fs_unix.symlink("/dev/null", "/lib/systemd/system/broken_sym_example.service")
    fs_unix.map_file("/usr/lib/systemd/system/example2.service", systemd_service_2)
    fs_unix.map_file("/etc/init.d/example", initd_service_1)
    target_unix_users.add_plugin(ServicesPlugin)

    results = list(target_unix_users.services())
    assert len(results) == 4

    assert results[0].name == "example.service"
    expected_config_1 = 'Unit_Description="an example systemd service"  Unit_After="foobar.service"  Unit_Requires="foo.service bar.service"  Service_Type="simple"  Service_ExecStart="/usr/sbin/simple-command --key value"  Service_SyslogIdentifier=""  Service_TimeoutStopSec="5"  Install_WantedBy="multi-user.target"  Install_Alias="example.service"'  # noqa E501
    assert results[0].config == expected_config_1
    assert str(results[0].source) == "/lib/systemd/system/example.service"

    assert results[1].name == "broken_sym_example.service"
    assert results[1].config is None
    assert str(results[1].source) == "/lib/systemd/system/broken_sym_example.service"

    assert results[2].name == "example2.service"
    expected_config_2 = 'Unit_Description="an example systemd service"  Unit_After="foobar.service"  Unit_Requires="foo.service bar.service"  Service_Type="simple"  ExecStart=/bin/bash -c \'exec /usr/bin/example param1 --param2=value2 -P3value3 -param4 value4; \\  exit 0\'  Service_SyslogIdentifier="example-service"  Service_TimeoutStopSec="5"  Install_WantedBy="multi-user.target"  Install_Alias="example.service"'  # noqa E501
    assert results[2].config == expected_config_2
    assert str(results[2].source) == "/usr/lib/systemd/system/example2.service"

    assert results[3].name == "example"
    assert results[3].config is None
    assert str(results[3].source) == "/etc/init.d/example"
