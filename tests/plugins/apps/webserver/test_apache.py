import textwrap
from datetime import datetime, timedelta, timezone
from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.webserver.apache import (
    LOG_FORMAT_ACCESS_COMBINED,
    LOG_FORMAT_ACCESS_COMMON,
    LOG_FORMAT_ACCESS_VHOST_COMBINED,
    ApachePlugin,
)
from dissect.target.target import Target
from tests._utils import absolute_path


def test_infer_access_log_format_combined() -> None:
    log_combined = (
        '127.0.0.1 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0 '
        "(Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 "
        'Safari/537.36"'
    )
    assert ApachePlugin.infer_access_log_format(log_combined) == LOG_FORMAT_ACCESS_COMBINED


def test_infer_access_log_format_vhost_combined() -> None:
    log_vhost_combined = (
        'example.com:80 127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 '
        '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/108.0.0.0 Safari/537.36"'
    )
    assert ApachePlugin.infer_access_log_format(log_vhost_combined) == LOG_FORMAT_ACCESS_VHOST_COMBINED


def test_infer_access_log_format_common() -> None:
    log_common = '127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
    assert ApachePlugin.infer_access_log_format(log_common) == LOG_FORMAT_ACCESS_COMMON


def test_infer_access_log_ipv6() -> None:
    log_combined = (
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - [20/Dec/2022:15:18:01 +0100] "GET / HTTP/1.1" 200 '
        '1126 "-" "curl/7.81.0"'
    )
    assert ApachePlugin.infer_access_log_format(log_combined) == LOG_FORMAT_ACCESS_COMBINED


def test_txt(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 6


def test_gz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/access.log.gz")
    fs_unix.map_file("var/log/apache2/access.log.1.gz", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4


def test_access_bz2(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/access.log.bz2")
    fs_unix.map_file("var/log/apache2/access.log.1.bz2", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4


def test_all_access_log_formats(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone(timedelta(hours=1))
    data_file = absolute_path("_data/plugins/apps/webserver/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 6

    combined_log = results[0]
    assert combined_log.ts == datetime(2022, 12, 19, 17, 6, 19, tzinfo=tz)
    assert combined_log.status_code == 200
    assert combined_log.remote_ip == "1.2.3.4"
    assert combined_log.remote_user == "-"
    assert combined_log.method == "GET"
    assert combined_log.uri == "/"
    assert combined_log.protocol == "HTTP/1.1"
    assert combined_log.referer == "Sample referer"
    assert (
        combined_log.useragent
        == "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 "
        "Safari/537.36"
    )

    vhost_combined_log = results[1]
    assert vhost_combined_log.ts == datetime(2022, 12, 19, 17, 25, 40, tzinfo=tz)
    assert vhost_combined_log.status_code == 200
    assert vhost_combined_log.remote_ip == "1.2.3.4"
    assert vhost_combined_log.remote_user == "-"
    assert vhost_combined_log.method == "GET"
    assert vhost_combined_log.uri == "/index.html"
    assert vhost_combined_log.protocol == "HTTP/1.1"
    assert vhost_combined_log.referer == "-"
    assert (
        vhost_combined_log.useragent
        == "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 "
        "Safari/537.36"
    )

    common_log = results[2]
    assert common_log.ts == datetime(2022, 12, 19, 17, 25, 48, tzinfo=tz)
    assert common_log.status_code == 200
    assert common_log.remote_ip == "4.3.2.1"
    assert common_log.remote_user == "-"
    assert common_log.method == "GET"
    assert common_log.uri == "/"
    assert common_log.protocol == "HTTP/1.1"
    assert common_log.referer is None
    assert common_log.useragent is None

    ipv6_log = results[3]
    assert ipv6_log.remote_ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert ipv6_log.protocol is None
    assert ipv6_log.bytes_sent == 0


def test_logrotate(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)
    fs_unix.map_file("var/log/apache2/access.log.1", data_file)
    fs_unix.map_file("var/log/apache2/access.log.2", data_file)
    fs_unix.map_file("var/log/apache2/access.log.3", data_file)

    target_unix.add_plugin(ApachePlugin)
    access_log_paths, error_log_paths = target_unix.apache.get_log_paths()

    assert len(access_log_paths) == 4
    assert len(error_log_paths) == 0


def test_custom_config(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("etc/apache2/apache2.conf", BytesIO(b'CustomLog "/custom/log/location/access.log" common'))
    fs_unix.map_file_fh("custom/log/location/access.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("custom/log/location/access.log.1", BytesIO(b"Foo1"))
    fs_unix.map_file_fh("custom/log/location/access.log.2", BytesIO(b"Foo2"))
    fs_unix.map_file_fh("custom/log/location/access.log.3", BytesIO(b"Foo3"))

    target_unix.add_plugin(ApachePlugin)
    access_log_paths, error_log_paths = target_unix.apache.get_log_paths()

    assert len(access_log_paths) == 4
    assert len(error_log_paths) == 0


def test_config_commented_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    config = """
    # CustomLog "/custom/log/location/old.log" common
    CustomLog "/custom/log/location/new.log" common
    # ErrorLog "/custom/log/location//old_error.log"
    ErrorLog "/custom/log/location//new_error.log"

    """
    fs_unix.map_file_fh("etc/httpd/conf/httpd.conf", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("custom/log/location/new.log", BytesIO(b"New"))
    fs_unix.map_file_fh("custom/log/location/old.log", BytesIO(b"Old"))
    fs_unix.map_file_fh("custom/log/location/old_error.log", BytesIO(b"Old"))
    fs_unix.map_file_fh("custom/log/location/new_error.log", BytesIO(b"New"))
    target_unix.add_plugin(ApachePlugin)

    access_log_paths, error_log_paths = target_unix.apache.get_log_paths()

    # Log paths are returned in alphabetical order
    assert str(access_log_paths[0]) == "/custom/log/location/new.log"
    assert str(access_log_paths[1]) == "/custom/log/location/old.log"

    assert str(error_log_paths[0]) == "/custom/log/location/new_error.log"
    assert str(error_log_paths[1]) == "/custom/log/location/old_error.log"


def test_error_txt(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/error.log")
    fs_unix.map_file("var/log/apache2/error.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.error())

    assert len(results) == 3
    assert all(str(record.source) == "/var/log/apache2/error.log" for record in results)


def test_all_error_log_formats(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/apache/error.log")
    fs_unix.map_file("var/log/apache2/error.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.error())

    assert len(results) == 3

    no_client_log = results[0]
    assert no_client_log.ts == datetime(2022, 12, 13, 13, 7, 21, 131489, tzinfo=timezone.utc)
    assert no_client_log.error_code == "AH00163"
    assert no_client_log.module == "mpm_prefork"
    assert no_client_log.level == "notice"
    assert no_client_log.pid == 218
    assert no_client_log.message == (
        "Apache/2.4.54 (Unix) mod_perl/2.0.10 Perl/v5.30.2 configured -- resuming normal operations"
    )

    client_log = results[1]
    assert client_log.ts == datetime(2011, 5, 12, 8, 28, 57, 652118, tzinfo=timezone.utc)
    assert client_log.error_code is None
    assert client_log.remote_ip == "::1"
    assert client_log.module == "core"
    assert client_log.level == "error"
    assert client_log.pid == 8777
    assert client_log.message == "File does not exist: /usr/local/apache2/htdocs/favicon.ico"

    log_with_source = results[2]
    assert log_with_source.ts == datetime(2019, 2, 1, 22, 3, 8, 320285, tzinfo=timezone.utc)
    assert log_with_source.error_code == "AH01626"
    assert log_with_source.remote_ip == "172.17.0.1"
    assert log_with_source.module == "authz_core"
    assert log_with_source.level == "debug"
    assert log_with_source.pid == 7
    assert log_with_source.message == "authorization result of <RequireAny>: granted"
    assert log_with_source.error_source == "mod_authz_core.c(820)"
