import textwrap
from datetime import datetime, timezone
from io import BytesIO

from dissect.target.plugins.apps.webserver.nginx import NginxPlugin
from tests._utils import absolute_path


def test_plugins_apps_webservers_nginx_txt(target_unix, fs_unix):
    data_file = absolute_path("_data/plugins/apps/webserver/nginx/access.log")
    fs_unix.map_file("var/log/nginx/access.log", data_file)

    target_unix.add_plugin(NginxPlugin)
    results = list(target_unix.nginx.access())

    assert len(results) == 2

    record = results[0]
    assert record.ts == datetime(2022, 12, 1, 0, 3, 57, tzinfo=timezone.utc)
    assert record.status_code == 200
    assert record.remote_ip == "1.2.3.4"
    assert record.remote_user == "admin"
    assert record.method == "GET"
    assert record.uri == "/"
    assert record.protocol == "HTTP/1.1"
    assert record.bytes_sent == 123


def test_plugins_apps_webservers_nginx_ipv6(target_unix, fs_unix):
    data_file = absolute_path("_data/plugins/apps/webserver/nginx/access.log")
    fs_unix.map_file("var/log/nginx/access.log", data_file)

    target_unix.add_plugin(NginxPlugin)
    results = list(target_unix.nginx.access())

    assert len(results) == 2

    record = results[1]
    assert record.remote_ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert record.status_code == 200
    assert record.remote_user == "-"
    assert record.method == "GET"
    assert record.uri == "/"
    assert record.protocol == "HTTP/1.1"
    assert record.bytes_sent == 123


def test_plugins_apps_webservers_nginx_gz(target_unix, fs_unix):
    data_file = absolute_path("_data/plugins/apps/webserver/nginx/access.log.gz")
    fs_unix.map_file("var/log/nginx/access.log.1.gz", data_file)

    target_unix.add_plugin(NginxPlugin)
    results = list(target_unix.nginx.access())

    assert len(results) == 2

    record = results[0]
    assert record.status_code == 200
    assert record.remote_ip == "1.2.3.4"
    assert record.remote_user == "admin"
    assert record.method == "GET"
    assert record.uri == "/"
    assert record.protocol == "HTTP/1.1"
    assert record.bytes_sent == 123


def test_plugins_apps_webservers_nginx_bz2(target_unix, fs_unix):
    data_file = absolute_path("_data/plugins/apps/webserver/nginx/access.log.bz2")
    fs_unix.map_file("var/log/nginx/access.log.1.bz2", data_file)

    target_unix.add_plugin(NginxPlugin)
    results = list(target_unix.nginx.access())

    assert len(results) == 2

    record = results[0]
    assert record.status_code == 200
    assert record.remote_ip == "1.2.3.4"
    assert record.remote_user == "admin"
    assert record.method == "GET"
    assert record.uri == "/"
    assert record.protocol == "HTTP/1.1"
    assert record.bytes_sent == 123


def test_plugins_apps_webservers_nginx_config(target_unix, fs_unix):
    config_file = absolute_path("_data/plugins/apps/webserver/nginx/nginx.conf")
    fs_unix.map_file("etc/nginx/nginx.conf", config_file)

    for i, log in enumerate(["access.log", "domain1.access.log", "domain2.access.log", "big.server.access.log"]):
        fs_unix.map_file_fh(f"opt/logs/{i}/{log}", BytesIO(b"Foo"))

    target_unix.add_plugin(NginxPlugin)
    log_paths = target_unix.nginx.get_log_paths()

    assert len(log_paths) == 4


def test_plugins_apps_webservers_nginx_config_logs_logrotated(target_unix, fs_unix):
    config_file = absolute_path("_data/plugins/apps/webserver/nginx/nginx.conf")
    fs_unix.map_file("etc/nginx/nginx.conf", config_file)
    fs_unix.map_file_fh("opt/logs/0/access.log", BytesIO(b"Foo1"))
    fs_unix.map_file_fh("opt/logs/0/access.log.1", BytesIO(b"Foo2"))
    fs_unix.map_file_fh("opt/logs/0/access.log.2", BytesIO(b"Foo3"))
    fs_unix.map_file_fh("opt/logs/1/domain1.access.log", BytesIO(b"Foo4"))
    fs_unix.map_file_fh("var/log/nginx/access.log", BytesIO(b"Foo5"))

    target_unix.add_plugin(NginxPlugin)
    log_paths = target_unix.nginx.get_log_paths()

    assert len(log_paths) == 5


def test_plugins_apps_webservers_nginx_config_commented_logs(target_unix, fs_unix):
    config = """
    # access_log      /foo/bar/old.log main;
    access_log      /foo/bar/new.log main;
    """
    fs_unix.map_file_fh("etc/nginx/nginx.conf", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("foo/bar/new.log", BytesIO(b"New"))
    fs_unix.map_file_fh("foo/bar/old.log", BytesIO(b"Old"))
    target_unix.add_plugin(NginxPlugin)

    log_paths = target_unix.nginx.get_log_paths()
    assert str(log_paths[0]) == "/foo/bar/old.log"
    assert str(log_paths[1]) == "/foo/bar/new.log"
