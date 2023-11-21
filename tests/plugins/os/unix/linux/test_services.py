import textwrap
from io import StringIO

import pytest

from dissect.target.plugins.os.unix.linux.services import (
    ServicesPlugin,
    parse_systemd_config,
)
from tests._utils import absolute_path


def test_services(target_unix_users, fs_unix):
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

    assert results[0].name == "example.service"
    expected_config_1 = 'Unit_Description="an example systemd service" Unit_After="foobar.service" Unit_Requires="foo.service bar.service" Service_Type="simple" Service_ExecStart="/usr/sbin/simple-command --key value" Service_SyslogIdentifier="" Service_TimeoutStopSec="5" Install_WantedBy="multi-user.target" Install_Alias="example.service"'  # noqa E501
    assert results[0].config == expected_config_1
    assert str(results[0].source) == "/lib/systemd/system/example.service"

    assert results[1].name == "broken_sym_example.service"
    assert results[1].config is None
    assert str(results[1].source) == "/lib/systemd/system/broken_sym_example.service"

    assert results[2].name == "example2.service"
    expected_config_2 = 'Unit_Description="an example systemd service" Unit_After="foobar.service" Unit_Requires="foo.service bar.service" Service_Type="simple" Service_ExecStart="/bin/bash -c \'exec /usr/bin/example param1 --param2=value2 -P3value3 -param4 value4; exit 0\'" Service_SyslogIdentifier="example-service" Service_TimeoutStopSec="5" Install_WantedBy="multi-user.target" Install_Alias="example.service"'  # noqa E501
    assert results[2].config == expected_config_2
    assert str(results[2].source) == "/usr/lib/systemd/system/example2.service"

    assert results[3].name == "example"
    assert results[3].config is None
    assert str(results[3].source) == "/etc/init.d/example"


@pytest.mark.parametrize(
    "assignment, expected_value",
    [
        ("[Unit]\nsystemd = help:me", 'Unit_systemd="help:me"'),
        ("[Unit]\nhelp:me = systemd", 'Unit_help:me="systemd"'),
        ("[Unit]\nempty_value=", 'Unit_empty_value=""'),
        ("[Unit]\nnew_lines=hello \\\nworld", 'Unit_new_lines="hello world"'),
        ("[Unit]\nnew_lines=hello \\\nworld\\\ntest", 'Unit_new_lines="hello world test"'),
        ("[Unit]\ntest", 'Unit_test="None"'),
        ("[Unit]\nnew_lines=hello \\\n#Comment\n;Comment2\nworld", 'Unit_new_lines="hello world"'),
        ("[Unit]\nlines=hello \\\nworld\\\n\ntest", 'Unit_lines="hello world test"'),
        (
            "[Unit]\nDescription=Online ext4 Metadata Check for %I",
            'Unit_Description="Online ext4 Metadata Check for %I"',
        ),
        ("[Unit]\ntest=hello\tme", 'Unit_test="hello\tme"'),
    ],
)
def test_systemd(assignment, expected_value):
    data = parse_systemd_config(StringIO(assignment))
    assert data == expected_value


@pytest.mark.xfail
def test_systemd_known_fails():
    # While this should return `Hello world test help`,
    # the configparser attempts to append `help` as a value to the list of options
    # belonging to the key before it `test\\`.
    # However, `test\\` is `None` or empty in this case it attempts to append on a NoneType object.
    # The future fix would to create a custom Systemd ConfigParser
    systemd_config = """
    [Unit]
    new_lines=hello \\
    world\\
    test\\
     help
    """
    parse_systemd_config(StringIO(textwrap.dedent(systemd_config)))
