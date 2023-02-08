from datetime import datetime, timezone
from io import BytesIO

from dissect.target.plugins.apps.webservers.nginx import NginxPlugin

from ._utils import absolute_path


def test_plugins_apps_webservers_nginx_txt(target_unix, fs_unix):
    fs_unix.map_file_fh("/etc/timezone", BytesIO("Etc/UTC".encode()))
    data_file = absolute_path("data/webservers/nginx/access.log")
    fs_unix.map_file("var/log/nginx/access.log", data_file)
    target_unix.add_plugin(NginxPlugin)

    results = list(target_unix.nginx())
    assert len(results) == 2

    log = results[0]
    assert log.ts == datetime(2022, 12, 1, 0, 3, 57, tzinfo=timezone.utc)
    assert log.status_code == 200
    assert log.remote_ip == "1.2.3.4"
    assert log.remote_user == "admin"
    assert log.request == "GET / HTTP/1.1"
    assert log.bytes_sent == 123


def test_plugins_apps_webservers_nginx_ipv6(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/nginx/access.log")
    fs_unix.map_file("var/log/nginx/access.log", data_file)
    target_unix.add_plugin(NginxPlugin)

    results = list(target_unix.nginx())
    assert len(results) == 2

    log = results[1]
    assert log.remote_ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert log.status_code == 200
    assert log.remote_user == "-"
    assert log.request == "GET / HTTP/1.1"
    assert log.bytes_sent == 123


def test_plugins_apps_webservers_nginx_gz(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/nginx/access.log.gz")
    fs_unix.map_file("var/log/nginx/access.log.1.gz", data_file)
    target_unix.add_plugin(NginxPlugin)

    results = list(target_unix.nginx())
    assert len(results) == 2

    log = results[0]
    assert log.status_code == 200
    assert log.remote_ip == "1.2.3.4"
    assert log.remote_user == "admin"
    assert log.request == "GET / HTTP/1.1"
    assert log.bytes_sent == 123


def test_plugins_apps_webservers_nginx_bz2(target_unix, fs_unix):
    data_file = absolute_path("data/webservers/nginx/access.log.bz2")
    fs_unix.map_file("var/log/nginx/access.log.1.bz2", data_file)
    target_unix.add_plugin(NginxPlugin)

    results = list(target_unix.nginx())
    assert len(results) == 2

    log = results[0]
    assert log.status_code == 200
    assert log.remote_ip == "1.2.3.4"
    assert log.remote_user == "admin"
    assert log.request == "GET / HTTP/1.1"
    assert log.bytes_sent == 123


def test_plugins_apps_webservers_nginx_config(target_unix, fs_unix):
    config_file = absolute_path("data/webservers/nginx/nginx.conf")
    fs_unix.map_file("etc/nginx/nginx.conf", config_file)

    for i, log in enumerate(["access.log", "domain1.access.log", "domain2.access.log", "big.server.access.log"]):
        fs_unix.map_file_fh(f"opt/logs/{i}/{log}", BytesIO("Foo".encode()))

    nginx = NginxPlugin(target_unix)
    assert len(nginx.log_paths) == 4
