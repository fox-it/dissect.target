from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.webserver.nginx import NginxPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_nginx_txt(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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


def test_nginx_ipv6(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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


def test_nginx_gz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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


def test_nginx_bz2(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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


def test_nginx_config(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    config_file = absolute_path("_data/plugins/apps/webserver/nginx/nginx.conf")
    fs_unix.map_file("etc/nginx/nginx.conf", config_file)

    for i, log in enumerate(["access.log", "domain1.access.log", "domain2.access.log", "big.server.access.log"]):
        fs_unix.map_file_fh(f"opt/logs/{i}/{log}", BytesIO(b"Foo"))

    target_unix.add_plugin(NginxPlugin)

    assert len(target_unix.nginx.access_paths) == 4
    assert len(target_unix.nginx.error_paths) == 0


def test_nginx_config_logs_logrotated(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    config_file = absolute_path("_data/plugins/apps/webserver/nginx/nginx.conf")
    fs_unix.map_file("etc/nginx/nginx.conf", config_file)
    fs_unix.map_file_fh("opt/logs/0/access.log", BytesIO(b"Foo1"))
    fs_unix.map_file_fh("opt/logs/0/access.log.1", BytesIO(b"Foo2"))
    fs_unix.map_file_fh("opt/logs/0/access.log.2", BytesIO(b"Foo3"))
    fs_unix.map_file_fh("opt/logs/1/domain1.access.log", BytesIO(b"Foo4"))
    fs_unix.map_file_fh("var/log/nginx/access.log", BytesIO(b"Foo5"))

    target_unix.add_plugin(NginxPlugin)

    assert len(target_unix.nginx.access_paths) == 5
    assert len(target_unix.nginx.error_paths) == 0


def test_nginx_config_commented_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    config = """
    # access_log      /foo/bar/old.log main;
    access_log      /foo/bar/new.log main;

    # error_log         /foo/bar/error/old.log warn;
    error_log               /foo/bar/error/new.log;
    """
    fs_unix.map_file_fh("etc/nginx/nginx.conf", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("foo/bar/new.log", BytesIO(b"New"))
    fs_unix.map_file_fh("foo/bar/old.log", BytesIO(b"Old"))
    fs_unix.map_file_fh("foo/bar/error/new.log", BytesIO(b""))
    fs_unix.map_file_fh("foo/bar/error/old.log", BytesIO(b""))

    target_unix.add_plugin(NginxPlugin)

    assert len(target_unix.nginx.access_paths) == 2
    assert len(target_unix.nginx.error_paths) == 2

    assert sorted(map(str, target_unix.nginx.access_paths)) == ["/foo/bar/new.log", "/foo/bar/old.log"]
    assert sorted(map(str, target_unix.nginx.error_paths)) == ["/foo/bar/error/new.log", "/foo/bar/error/old.log"]


def test_nginx_error_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect and parse nginx error logs correctly."""

    errors = """
    2025/01/31 13:37:01 [alert] 12345#12345: this is a message
    2025/01/31 13:37:02 [alert] 12345#12345: this is another message
    2025/01/31 13:37:03 [alert] 12345#12345: and a third message!
    """
    fs_unix.map_file_fh("var/log/nginx/error.log", BytesIO(textwrap.dedent(errors).encode()))

    target_unix.add_plugin(NginxPlugin)
    records = list(target_unix.nginx.error())

    assert len(records) == 3

    assert records[0].ts == datetime(2025, 1, 31, 13, 37, 1, tzinfo=timezone.utc)
    assert records[0].level == "alert"
    assert records[0].message == "this is a message"
    assert records[0].source == "/var/log/nginx/error.log"


def test_nginx_parse_config(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we parse config files and their include directives correctly."""

    base_conf = """
    user www www;
    server {
        listen 1337;
        server_name example;
        index index.html;
        root /var/www/html;
        include some.conf;
        access_log /some/access.log;
    }
    include /more/confs/*.conf;
    """
    fs_unix.map_file_fh("/etc/nginx/nginx.conf", BytesIO(textwrap.dedent(base_conf).encode()))

    some_conf = """
    error_log /some/error.log;
    """
    fs_unix.map_file_fh("/etc/nginx/some.conf", BytesIO(textwrap.dedent(some_conf).encode()))

    more_confs_one = """
    server {
        listen 80;
        server_name eighty;
        index index.html;
        root /var/www/eighty;
        access_log /eighty/access.log;
        include /bla/foo.conf;
    }
    """
    fs_unix.map_file_fh("/more/confs/one.conf", BytesIO(textwrap.dedent(more_confs_one).encode()))

    foo_conf = """
    error_log /eighty/error.log;
    """
    fs_unix.map_file_fh("/bla/foo.conf", BytesIO(textwrap.dedent(foo_conf).encode()))

    fs_unix.map_file_fh("/some/access.log", BytesIO(b""))
    fs_unix.map_file_fh("/some/error.log", BytesIO(b""))
    fs_unix.map_file_fh("/eighty/access.log.1", BytesIO(b""))
    fs_unix.map_file_fh("/eighty/error.log.1", BytesIO(b""))

    target_unix.add_plugin(NginxPlugin)

    assert sorted(map(str, target_unix.nginx.access_paths)) == [
        "/eighty/access.log.1",
        "/some/access.log",
    ]
    assert sorted(map(str, target_unix.nginx.error_paths)) == [
        "/eighty/error.log.1",
        "/some/error.log",
    ]

    assert sorted(map(str, target_unix.nginx.host_paths)) == [
        "/etc/nginx/nginx.conf",
        "/more/confs/one.conf",
    ]

    records = sorted(target_unix.nginx.hosts(), key=lambda r: r.source)

    assert len(records) == 2

    assert records[0].ts
    assert records[0].server_name == "example"
    assert records[0].server_port == 1337
    assert records[0].root_path == "/var/www/html"
    assert records[0].access_log_config == "/some/access.log"
    assert not records[0].error_log_config
    assert records[0].source == "/etc/nginx/nginx.conf"

    assert records[1].ts
    assert records[1].server_name == "eighty"
    assert records[1].server_port == 80
    assert records[1].root_path == "/var/www/eighty"
    assert records[1].access_log_config == "/eighty/access.log"
    assert not records[1].error_log_config
    assert records[1].source == "/more/confs/one.conf"
