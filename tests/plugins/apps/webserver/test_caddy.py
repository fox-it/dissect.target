import textwrap
from datetime import timedelta, timezone
from io import BytesIO

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.webserver.caddy import CaddyPlugin
from tests._utils import absolute_path


def test_plugins_apps_webservers_caddy_txt(target_unix, fs_unix):
    tz = timezone(timedelta(hours=-7))
    fs_unix.map_file_fh(
        "var/log/caddy_access.log",
        BytesIO(b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326'),
    )

    target_unix.add_plugin(CaddyPlugin)
    results = list(target_unix.caddy.access())

    assert len(results) == 1

    record = results[0]
    assert record.remote_ip == "127.0.0.1"
    assert record.ts == dt(2000, 10, 10, 13, 55, 36, tzinfo=tz)
    assert record.method == "GET"
    assert record.uri == "/apache_pb.gif"
    assert record.protocol == "HTTP/1.1"
    assert record.status_code == 200
    assert record.bytes_sent == 2326


def test_plugins_apps_webservers_caddy_json(target_unix, fs_unix):
    fs_unix.map_file(
        "var/log/caddy_access.log",
        absolute_path("_data/plugins/apps/webserver/caddy/access.log"),
    )

    target_unix.add_plugin(CaddyPlugin)
    results = list(target_unix.caddy.access())

    assert len(results) == 2

    record = results[0]
    assert record.remote_ip == "172.17.0.1"
    assert record.ts == dt(2023, 2, 6, 15, 5, 49, 64393, tzinfo=timezone.utc)
    assert record.method == "GET"
    assert record.uri == "/"
    assert record.protocol == "HTTP/1.1"
    assert record.status_code == 200
    assert record.bytes_sent == 12


def test_plugins_apps_webservers_caddy_config(target_unix, fs_unix):
    config_file = absolute_path("_data/plugins/apps/webserver/caddy/Caddyfile")
    fs_unix.map_file("etc/caddy/Caddyfile", config_file)

    fs_unix.map_file("etc/caddy/Caddyfile", config_file)
    fs_unix.map_file_fh("var/www/log/access.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("var/log/caddy/access.log", BytesIO(b"Foo"))

    target_unix.add_plugin(CaddyPlugin)
    log_paths = target_unix.caddy.get_log_paths()

    assert len(log_paths) == 2
    assert str(log_paths[0]) == "/var/log/caddy/access.log"
    assert str(log_paths[1]) == "/var/www/log/access.log"


def test_plugins_apps_webservers_caddy_config_logs_logrotated(target_unix, fs_unix):
    config_file = absolute_path("_data/plugins/apps/webserver/caddy/Caddyfile")
    fs_unix.map_file("etc/caddy/Caddyfile", config_file)

    fs_unix.map_file_fh("var/www/log/access.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("var/www/log/access.log.1", BytesIO(b"Foo1"))
    fs_unix.map_file_fh("var/www/log/access.log.2", BytesIO(b"Foo2"))
    fs_unix.map_file_fh("var/www/log/access.log.3", BytesIO(b"Foo3"))

    target_unix.add_plugin(CaddyPlugin)
    log_paths = target_unix.caddy.get_log_paths()

    assert len(log_paths) == 4


def test_plugins_apps_webservers_caddy_config_commented(target_unix, fs_unix):
    config = """
    root /var/www/html
    1.example.com {
        log {
            # output file log/old.log
            output file log/new.log
        }
    }
    # 2.example.com {
    #     log {
    #         output file /completely/disabled/access.log
    #     }
    # }
    """
    fs_unix.map_file_fh("etc/caddy/Caddyfile", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("var/www/log/old.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("var/www/log/new.log", BytesIO(b"Foo"))
    fs_unix.map_file_fh("completely/disabled/access.log", BytesIO(b"Foo"))

    target_unix.add_plugin(CaddyPlugin)
    log_paths = target_unix.caddy.get_log_paths()

    assert len(log_paths) == 3
    assert str(log_paths[0]) == "/var/www/log/old.log"
    assert str(log_paths[1]) == "/var/www/log/new.log"
    assert str(log_paths[2]) == "/completely/disabled/access.log"
