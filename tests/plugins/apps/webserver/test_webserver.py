from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.apps.webserver import apache, caddy, iis, nginx, webserver
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_access_logs_webserver_namespace_unix(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    apache_access_file = absolute_path("_data/plugins/apps/webserver/apache/access.log")
    apache_error_file = absolute_path("_data/plugins/apps/webserver/apache/error.log")
    nginx_file = absolute_path("_data/plugins/apps/webserver/nginx/access.log")
    caddy_file = absolute_path("_data/plugins/apps/webserver/caddy/access.log")

    fs_unix.map_file("var/log/apache2/access.log", apache_access_file)
    fs_unix.map_file("var/log/apache2/error.log", apache_error_file)
    fs_unix.map_file("var/log/nginx/access.log", nginx_file)
    fs_unix.map_file("var/log/caddy_access.log", caddy_file)

    target_unix.add_plugin(apache.ApachePlugin)
    target_unix.add_plugin(nginx.NginxPlugin)
    target_unix.add_plugin(caddy.CaddyPlugin)

    # Register the IISLogsPlugin even though it is not compatible, to prevent it from being 'autodiscovered'
    target_unix.add_plugin(iis.IISLogsPlugin, check_compatible=False)
    target_unix.add_plugin(webserver.WebserverPlugin)

    access_logs = list(target_unix.webserver.access())

    assert len(access_logs) == 10
    assert len([record for record in access_logs if "apache" in record.source.as_posix()]) == 6
    assert len([record for record in access_logs if "nginx" in record.source.as_posix()]) == 2
    assert len([record for record in access_logs if "caddy" in record.source.as_posix()]) == 2

    error_logs = list(target_unix.webserver.error())
    assert len(error_logs) == 3

    # The logs function should yield both access and error logs
    assert len(list(target_unix.webserver.logs())) == 13


def test_access_logs_webserver_namespace_windows(target_win: Target, fs_win: VirtualFilesystem) -> None:
    config_path = absolute_path("_data/plugins/apps/webserver/iis/iis-applicationHost-iis.config")
    data_dir = absolute_path("_data/plugins/apps/webserver/iis/iis-logs-iis")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/iis-logs", data_dir)

    target_win.add_plugin(iis.IISLogsPlugin)
    target_win.add_plugin(webserver.WebserverPlugin)

    access_logs = list(target_win.webserver.access())
    assert len(access_logs) == 10
