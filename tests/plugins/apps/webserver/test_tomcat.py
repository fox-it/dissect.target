from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.webserver.tomcat import TomcatPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_unix_logs_default_install(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse the Tomcat 10 access logs of a default UNIX install."""
    fs_unix.map_dir("/var/lib/tomcat10/", absolute_path("_data/plugins/apps/webserver/tomcat/tomcat/"))
    fs_unix.symlink("/etc/tomcat10/", "/var/lib/tomcat10/conf/")
    fs_unix.symlink("/var/log/tomcat10/", "/var/lib/tomcat10/logs/")

    fs_unix.map_file("/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server.xml"))
    fs_unix.map_file(
        "/var/log/tomcat10/localhost_access_log.2026-01-01.txt",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )

    target_unix.add_plugin(TomcatPlugin)
    records = list(target_unix.tomcat.access())
    assert len(records) == 2

    assert records[0].ts == datetime(2026, 1, 1, 13, 37, 1, tzinfo=timezone.utc)
    assert records[0].status_code == 200
    assert records[0].remote_ip == "0:0:0:0:0:0:0:1"
    assert records[0].remote_user is None
    assert records[0].method == "GET"
    assert records[0].uri == "/"
    assert records[0].protocol == "HTTP/1.1"
    assert records[0].bytes_sent == 1337

    assert records[1].ts == datetime(2026, 1, 1, 13, 37, 2, tzinfo=timezone.utc)
    assert records[1].status_code == 404
    assert records[1].remote_ip == "1.2.3.4"
    assert records[1].remote_user is None
    assert records[1].method == "GET"
    assert records[1].uri == "/foo"
    assert records[1].protocol == "HTTP/1.1"
    assert records[1].bytes_sent == 1337


def test_unix_logs_combined_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse the access logs of a Tomcat 10 UNIX install with combined log format."""
    fs_unix.map_file(
        "/var/log/tomcat10/localhost_access_log.2026-01-01.txt",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.combined.txt"),
    )

    target_unix.add_plugin(TomcatPlugin)
    records = list(target_unix.tomcat.access())
    assert len(records) == 2

    assert records[0].referer is None
    assert records[0].useragent == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"

    assert records[1].webserver == "tomcat"
    assert not records[1].remote_user
    assert records[1].remote_ip == "1.2.3.4"
    assert records[1].method == "GET"
    assert records[1].uri == "/foo"
    assert not records[1].query
    assert records[1].protocol == "HTTP/1.1"
    assert records[1].status_code == 404
    assert records[1].bytes_sent == 1337
    assert records[1].referer == "http://127.0.0.1/bar"
    assert records[1].useragent == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"
    assert records[1].source == "/var/log/tomcat10/localhost_access_log.2026-01-01.txt"


def test_unix_hosts_default_install(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Tomcat 10 UNIX hosts defined in ``server.xml`` files."""
    fs_unix.map_dir("/var/lib/tomcat10/", absolute_path("_data/plugins/apps/webserver/tomcat/tomcat/"))
    fs_unix.symlink("/etc/tomcat10/", "/var/lib/tomcat10/conf/")
    fs_unix.symlink("/var/log/tomcat10/", "/var/lib/tomcat10/logs/")

    fs_unix.map_file("/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server.xml"))
    fs_unix.map_file(
        "/var/log/tomcat10/localhost_access_log.2026-01-01.txt",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )

    target_unix.add_plugin(TomcatPlugin)
    records = list(target_unix.tomcat.hosts())
    assert len(records) == 1  # Test deduplication of symlinked install dirs.

    assert records[0].webserver == "tomcat"
    assert records[0].server_name == "localhost"
    assert records[0].server_port == 8080
    assert records[0].access_log_config == "logs/localhost_access_log*.txt"
    assert records[0].source == "/var/lib/tomcat10/conf/server.xml"


def test_unix_certificates_default_install_v8(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Tomcat version <=8 TLS host certificates."""
    fs_unix.map_dir("/var/lib/tomcat8/", absolute_path("_data/plugins/apps/webserver/tomcat/tomcat/"))
    fs_unix.symlink("/etc/tomcat8/", "/var/lib/tomcat8/conf/")
    fs_unix.symlink("/var/log/tomcat8/", "/var/lib/tomcat8/logs/")

    fs_unix.map_file("/etc/tomcat8/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server_tls_v8.xml"))
    fs_unix.map_file(
        "/etc/tomcat8/localhost.crt", absolute_path("_data/plugins/apps/webserver/certificates/example.crt")
    )
    fs_unix.map_file(
        "/etc/tomcat8/localhost.key", absolute_path("_data/plugins/apps/webserver/certificates/example.key")
    )
    target_unix.add_plugin(TomcatPlugin)

    records = list(target_unix.tomcat.hosts())
    assert records[0].server_port == 8443
    assert records[0].tls_certificate == "/var/lib/tomcat8/conf/localhost.crt"
    assert records[0].tls_key == "/var/lib/tomcat8/conf/localhost.key"

    records = list(target_unix.tomcat.certificates())
    assert len(records) == 1

    assert records[0].fingerprint.md5 == "a218ac9b6dbdaa8b23658c4d18c1cfc1"
    assert records[0].fingerprint.sha1 == "6566d8ebea1feb4eb3d12d9486cddb69e4e9e827"
    assert records[0].fingerprint.sha256 == "7221d881743505f13b7bfe854bdf800d7f0cd22d34307ed7157808a295299471"
    assert records[0].serial_number == 21067204948278457910649605551283467908287726794
    assert records[0].serial_number_hex == "03b0afa702c33e37fffd40e0c402b2120c1284ca"
    assert records[0].issuer_dn == "C=AU,ST=Some-State,O=Internet Widgits Pty Ltd,CN=example.com"
    assert records[0].source == "/var/lib/tomcat8/conf/localhost.crt"


def test_unix_certificates_default_install_v10(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Tomcat 10 UNIX host certificates."""
    fs_unix.map_dir("/var/lib/tomcat10/", absolute_path("_data/plugins/apps/webserver/tomcat/tomcat/"))
    fs_unix.symlink("/etc/tomcat10/", "/var/lib/tomcat10/conf/")
    fs_unix.symlink("/var/log/tomcat10/", "/var/lib/tomcat10/logs/")

    fs_unix.map_file("/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server_tls.xml"))
    fs_unix.map_file(
        "/etc/tomcat10/localhost.crt", absolute_path("_data/plugins/apps/webserver/certificates/example.crt")
    )
    fs_unix.map_file(
        "/etc/tomcat10/localhost.key", absolute_path("_data/plugins/apps/webserver/certificates/example.key")
    )
    target_unix.add_plugin(TomcatPlugin)

    records = list(target_unix.tomcat.hosts())
    assert len(records) == 1

    assert records[0].server_port == 8443
    assert records[0].tls_certificate == "/var/lib/tomcat10/conf/localhost.crt"
    assert records[0].tls_key == "/var/lib/tomcat10/conf/localhost.key"

    records = list(target_unix.tomcat.certificates())
    assert len(records) == 1

    assert records[0].fingerprint.md5 == "a218ac9b6dbdaa8b23658c4d18c1cfc1"
    assert records[0].fingerprint.sha1 == "6566d8ebea1feb4eb3d12d9486cddb69e4e9e827"
    assert records[0].fingerprint.sha256 == "7221d881743505f13b7bfe854bdf800d7f0cd22d34307ed7157808a295299471"
    assert records[0].serial_number == 21067204948278457910649605551283467908287726794
    assert records[0].serial_number_hex == "03b0afa702c33e37fffd40e0c402b2120c1284ca"
    assert records[0].issuer_dn == "C=AU,ST=Some-State,O=Internet Widgits Pty Ltd,CN=example.com"
    assert records[0].source == "/var/lib/tomcat10/conf/localhost.crt"


def test_unix_logs_custom_log_location(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can find and parse a custom Tomcat 10 log location directive."""
    fs_unix.map_dir("/var/lib/tomcat10/", absolute_path("_data/plugins/apps/webserver/tomcat/tomcat/"))
    fs_unix.symlink("/etc/tomcat10/", "/var/lib/tomcat10/conf/")
    fs_unix.symlink("/var/log/tomcat10/", "/var/lib/tomcat10/logs/")

    fs_unix.map_file(
        "/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server_changed_log_file.xml")
    )
    fs_unix.map_file(
        "/var/log/tomcat10/example.com_access_log.2026-01-01.log",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )

    target_unix.add_plugin(TomcatPlugin)
    records = list(target_unix.tomcat.access())
    assert len(records) == 2


def test_unix_logs_custom_log_location_no_install(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can find and parse a custom Tomcat 10 log location without a full Tomcat install."""
    fs_unix.map_file(
        "/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server_changed_log_file.xml")
    )
    fs_unix.map_file(
        "/var/log/tomcat10/example.com_access_log.2026-01-01.log",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )

    target_unix.add_plugin(TomcatPlugin)
    records = list(target_unix.tomcat.access())
    assert len(records) == 2


def test_unix_logs_deleted_install(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we still find a custom log file if the current ``server.xml`` no longer references to it."""
    fs_unix.map_file("/etc/tomcat10/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server.xml"))
    fs_unix.map_file(
        "/var/log/tomcat10/localhost_access_log.2026-01-01.txt",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )
    target_unix.add_plugin(TomcatPlugin)

    records = list(target_unix.tomcat.access())
    assert len(records) == 2

    records = list(target_unix.tomcat.hosts())
    assert len(records) == 1

    assert records[0].webserver == "tomcat"
    assert records[0].server_name == "localhost"
    assert records[0].server_port == 8080
    assert records[0].access_log_config == "logs/localhost_access_log*.txt"
    assert records[0].source == "/etc/tomcat10/server.xml"


def test_win_logs_default_install(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can find and detect a XAMPP Tomcat install on a Windows machine."""
    fs_win.map_file("xampp/tomcat/conf/server.xml", absolute_path("_data/plugins/apps/webserver/tomcat/server.xml"))
    fs_win.map_file(
        "xampp/tomcat/logs/localhost_access_log.2026-01-01.txt",
        absolute_path("_data/plugins/apps/webserver/tomcat/localhost_access_log.2026-01-01.txt"),
    )
    target_win.add_plugin(TomcatPlugin)

    records = list(target_win.tomcat.access())
    assert len(records) == 2

    records = list(target_win.tomcat.hosts())
    assert len(records) == 1

    assert records[0].webserver == "tomcat"
    assert records[0].server_name == "localhost"
    assert records[0].server_port == 8080
    assert records[0].access_log_config == "logs/localhost_access_log*.txt"
    assert records[0].source == "\\sysvol\\xampp\\tomcat\\conf\\server.xml"
