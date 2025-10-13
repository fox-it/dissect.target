from __future__ import annotations

from io import BytesIO
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


def test_services_systemd_drop_folder(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly parse systemd ``.service`` and drop folder ``.conf`` files. Data based on Ubuntu 22.04 LTS default files."""  # noqa: E501

    fs_unix.map_file(
        "/lib/systemd/system/systemd-localed.service",
        str(absolute_path("_data/plugins/os/unix/linux/services/systemd-localed.service")),
    )
    fs_unix.map_file(
        "/lib/systemd/system/systemd-localed.service.d/locale-gen.conf",
        str(absolute_path("_data/plugins/os/unix/linux/services/locale-gen.conf")),
    )
    fs_unix.map_file_fh(
        "/lib/systemd/system/systemd-localed.service.d/test.conf",
        BytesIO(b"[Unit]\nDescription=Another Description\n"),
    )

    target_unix.add_plugin(ServicesPlugin)
    results = list(target_unix.services())

    # Make sure we convert duplicate values to a list
    assert results[0].Unit_Description == ["Locale Service", "Another Description"]

    # Make sure we convert multiple entries to a list
    assert results[0].Unit_Documentation == [
        "man:systemd-localed.service(8)",
        "man:locale.conf(5)",
        "man:vconsole.conf(5)",
        "man:org.freedesktop.locale1(5)",
    ]

    # Make sure we map empty values to None
    assert results[0].Service_CapabilityBoundingSet is None

    # Make sure we merge .service entries and drop file entries into a single list
    assert results[0].Service_ReadWritePaths == ["/etc", "/usr/lib/locale", "/usr/lib/locale/"]

    # We do not have visibility in the parsed drop files since that is handled internally by the drop file configparser
    assert results[0].source == "/lib/systemd/system/systemd-localed.service"
