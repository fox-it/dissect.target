from datetime import datetime
from zoneinfo import ZoneInfo
from io import BytesIO

from dissect.target.plugins.apps.webservers.caddy import CaddyPlugin

from ._utils import absolute_path


def test_plugins_apps_webservers_caddy_txt(target_unix, fs_unix):
    fs_unix.map_file_fh("etc/timezone", BytesIO(b"America/Phoenix"))
    fs_unix.map_file_fh(
        "var/log/caddy_access.log",
        BytesIO(b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326'),
    )
    target_unix.add_plugin(CaddyPlugin)
    results = list(target_unix.caddy())
    assert len(results) == 1
    assert results[0].remote_ip == "127.0.0.1"
    assert results[0].ts == datetime(2000, 10, 10, 13, 55, 36, tzinfo=ZoneInfo("America/Phoenix"))
    assert results[0].url == "GET /apache_pb.gif HTTP/1.1"
    assert results[0].status_code == 200
    assert results[0].bytes_sent == 2326


def test_plugins_apps_webservers_caddy_config(target_unix, fs_unix):
    config_file = absolute_path("data/webservers/caddy/Caddyfile")
    fs_unix.map_file("etc/caddy/Caddyfile", config_file)

    fs_unix.map_file("etc/caddy/Caddyfile", config_file)
    fs_unix.map_file_fh("var/www/log/access.log", BytesIO("Foo".encode()))
    fs_unix.map_file_fh("var/log/caddy/access.log", BytesIO("Foo".encode()))

    caddy = CaddyPlugin(target_unix)
    assert len(caddy.log_paths) == 2
    assert str(caddy.log_paths[0]) == "/var/log/caddy"
    assert str(caddy.log_paths[1]) == "/var/www/log"
