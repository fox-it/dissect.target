from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.apps.webserver.apache import ApachePlugin
from dissect.target.plugins.apps.webserver.citrix import (
    LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME,
    LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME_WITH_HEADERS,
    CitrixWebserverPlugin,
)
from dissect.target.plugins.apps.webserver.webserver import WebserverPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_infer_access_log_citrix_netscaler_combined_response_time() -> None:
    log_combined = (
        '127.0.0.1 - - [11/Aug/2023:08:30:00 +0000] [82775] "GET / HTTP/1.1" 200 18705 "-" "curl/7.78.0" "Time: 39770 '
        'microsecs"'
    )
    logformat = CitrixWebserverPlugin.infer_access_log_format(log_combined)
    assert logformat == LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME


def test_infer_access_log_citrix_netscaler_combined_response_time_with_headers() -> None:
    log_combined_with_headers = (
        '1.2.3.4 -> 5.6.7.8 - - [19/Dec/2022:17:25:48 +0100] [69420] "GET / HTTP/1.1" 200 1436 "-" "Mozilla/5.0 '
        '(Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36" '
        '"Time: 58774 microsecs"'
    )
    logformat = CitrixWebserverPlugin.infer_access_log_format(log_combined_with_headers)
    assert logformat == LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME_WITH_HEADERS


def test_access_logs(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    tz = timezone(timedelta(hours=1))
    data_file = absolute_path("_data/plugins/apps/webserver/citrix/httpaccess.log")
    fs_bsd.map_file("var/log/httpaccess.log", data_file)

    target_citrix.add_plugin(CitrixWebserverPlugin)

    results = list(target_citrix.citrix.access())

    citrix_netscaler_headers_combined_response_log = results[0]
    assert citrix_netscaler_headers_combined_response_log.ts == datetime(2022, 12, 19, 17, 25, 48, tzinfo=tz)
    assert citrix_netscaler_headers_combined_response_log.remote_ip == "1.2.3.4"
    assert citrix_netscaler_headers_combined_response_log.local_ip == "5.6.7.8"
    assert citrix_netscaler_headers_combined_response_log.status_code == 200
    assert citrix_netscaler_headers_combined_response_log.method == "GET"
    assert citrix_netscaler_headers_combined_response_log.uri == "/"
    assert citrix_netscaler_headers_combined_response_log.protocol == "HTTP/1.1"
    assert citrix_netscaler_headers_combined_response_log.referer is None
    assert (
        citrix_netscaler_headers_combined_response_log.useragent
        == "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 "
        "Safari/537.36"
    )
    assert citrix_netscaler_headers_combined_response_log.response_time_ms == 58
    assert citrix_netscaler_headers_combined_response_log.pid == 69420

    citrix_netscaler_headers_combined_response_log = results[1]
    assert citrix_netscaler_headers_combined_response_log.ts == datetime(2023, 8, 11, 8, 30, 0, tzinfo=timezone.utc)
    assert citrix_netscaler_headers_combined_response_log.remote_ip == "127.0.0.1"
    assert citrix_netscaler_headers_combined_response_log.status_code == 200
    assert citrix_netscaler_headers_combined_response_log.method == "GET"
    assert citrix_netscaler_headers_combined_response_log.uri == "/"
    assert citrix_netscaler_headers_combined_response_log.protocol == "HTTP/1.1"
    assert citrix_netscaler_headers_combined_response_log.referer is None
    assert citrix_netscaler_headers_combined_response_log.useragent == "curl/7.78.0"
    assert citrix_netscaler_headers_combined_response_log.response_time_ms == 39
    assert citrix_netscaler_headers_combined_response_log.pid == 82775


def test_error_logs(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    fs_bsd.map_file("var/log/httperror-vpn.log", BytesIO(b"Foo"))
    fs_bsd.map_file("var/log/httperror.log", BytesIO(b"Bar"))

    target_citrix.add_plugin(CitrixWebserverPlugin)

    assert len(target_citrix.citrix.error_paths) == 2


def test_access_logs_webserver_namespace(target_citrix: Target, fs_bsd: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webserver/citrix/httpaccess.log")
    fs_bsd.map_file("var/log/httpaccess.log", data_file)

    with pytest.raises(UnsupportedPluginError, match="Use the 'apps.webserver.citrix' apache plugin instead"):
        target_citrix.add_plugin(ApachePlugin)

    target_citrix.add_plugin(CitrixWebserverPlugin)
    target_citrix.add_plugin(WebserverPlugin)

    results_via_webserver_namespace = list(target_citrix.webserver.access())
    results_via_citrix_namespace = list(target_citrix.citrix.access())

    assert len(results_via_webserver_namespace) == 2
    assert len(results_via_citrix_namespace) == 2
    assert [str(r) for r in results_via_webserver_namespace] == [str(r) for r in results_via_citrix_namespace]
