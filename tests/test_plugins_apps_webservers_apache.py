import textwrap
from datetime import datetime, timedelta, timezone
from io import BytesIO

from dissect.target.plugins.apps.webservers.apache import (
    ApachePlugin,
    LogFormat,
    infer_log_format,
)

from ._utils import absolute_path


def test_plugins_apps_webservers_apache_infer_log_format_combined():
    log_combined = (
        '127.0.0.1 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0 '
        "(Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 "
        'Safari/537.36"'
    )
    assert infer_log_format(log_combined) == LogFormat.COMBINED


def test_plugins_apps_webservers_apache_nfer_log_format_vhost_combined():
    log_vhost_combined = (
        'example.com:80 127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 '
        '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/108.0.0.0 Safari/537.36"'
    )
    assert infer_log_format(log_vhost_combined) == LogFormat.VHOST_COMBINED


def test_plugins_apps_webservers_apache_infer_log_format_common():
    log_common = '127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
    assert infer_log_format(log_common) == LogFormat.COMMON


def test_plugins_apps_webservers_apache_infer_log_ipv6():
    log_combined = (
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - [20/Dec/2022:15:18:01 +0100] "GET / HTTP/1.1" 200 '
        '1126 "-" "curl/7.81.0"'
    )
    assert infer_log_format(log_combined) == LogFormat.COMBINED


def test_plugins_apps_webservers_apache_txt(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4


def test_plugins_apps_webservers_apache_gz(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/apache/access.log.gz")
    fs_unix.map_file("var/log/apache2/access.log.1.gz", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4


def test_plugins_apps_webservers_apache_bz2(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/apache/access.log.bz2")
    fs_unix.map_file("var/log/apache2/access.log.1.bz2", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4


def test_plugins_apps_webservers_apache_all_log_formats(target_unix, fs_unix):
    tz = timezone(timedelta(hours=1))
    data_file = absolute_path("data/webservers/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)

    target_unix.add_plugin(ApachePlugin)
    results = list(target_unix.apache.access())

    assert len(results) == 4

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


def test_plugins_apps_webservers_apache_logrotate(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/apache/access.log")
    fs_unix.map_file("var/log/apache2/access.log", data_file)
    fs_unix.map_file("var/log/apache2/access.log.1", data_file)
    fs_unix.map_file("var/log/apache2/access.log.2", data_file)
    fs_unix.map_file("var/log/apache2/access.log.3", data_file)

    target_unix.add_plugin(ApachePlugin)
    log_paths = target_unix.apache.get_log_paths()

    assert len(log_paths) == 4


def test_plugins_apps_webservers_apache_custom_config(target_unix, fs_unix):
    fs_unix.map_file_fh("etc/apache2/apache2.conf", BytesIO(b'CustomLog "/custom/log/location/access.log" common'))
    fs_unix.map_file_fh("custom/log/location/access.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("custom/log/location/access.log.1", BytesIO(b"Foo1"))
    fs_unix.map_file_fh("custom/log/location/access.log.2", BytesIO(b"Foo2"))
    fs_unix.map_file_fh("custom/log/location/access.log.3", BytesIO(b"Foo3"))

    target_unix.add_plugin(ApachePlugin)
    log_paths = target_unix.apache.get_log_paths()

    assert len(log_paths) == 4


def test_plugins_apps_webservers_apache_config_commented_logs(target_unix, fs_unix):
    config = """
    # CustomLog "/custom/log/location/old.log" common
    CustomLog "/custom/log/location/new.log" common
    """
    fs_unix.map_file_fh("etc/httpd/conf/httpd.conf", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("custom/log/location/new.log", BytesIO(b"New"))
    fs_unix.map_file_fh("custom/log/location/old.log", BytesIO(b"Old"))
    target_unix.add_plugin(ApachePlugin)

    log_paths = target_unix.apache.get_log_paths()
    assert str(log_paths[0]) == "/custom/log/location/old.log"
    assert str(log_paths[1]) == "/custom/log/location/new.log"
