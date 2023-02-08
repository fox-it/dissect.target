from datetime import datetime
from pathlib import Path
from unittest.mock import mock_open, patch
from zoneinfo import ZoneInfo

import pytest

from dissect.target.plugins.apps.webservers import iis

from ._utils import absolute_path


def test_iis_plugin_iis_format(target_win, fs_win, tmpdir_name):
    config_path = absolute_path("data/webservers/iis/iis-applicationHost-iis.config")
    data_dir = absolute_path("data/webservers/iis/iis-logs-iis")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/iis-logs", data_dir)

    target_win.add_plugin(iis.IISLogsPlugin)

    records = list(target_win.iis.logs())

    assert len(records) == 10
    assert {str(r.client_ip) for r in records} == {"127.0.0.1", "::1"}
    assert {str(r.site_name) for r in records} == {"W3SVC1"}
    assert {r.service_status_code for r in records} == {"304", "404", "200"}

    # check if metadata fields are present
    assert {r.log_format for r in records} == {"IIS"}
    assert {r.log_file for r in records} == {"sysvol/Users/John/iis-logs/W3SVC1/u_in211001.log"}
    assert {r.hostname for r in records} == {target_win.hostname}


def test_iis_plugin_w3c_format(target_win, fs_win, tmpdir_name):
    config_path = absolute_path("data/webservers/iis/iis-applicationHost-w3c.config")
    data_dir = absolute_path("data/webservers/iis/iis-logs-w3c")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/w3c-logs", data_dir)

    target_win.add_plugin(iis.IISLogsPlugin)

    records = list(target_win.iis.logs())

    assert len(records) == 20

    # first 6 records do not have custom fields and server_name is not set
    assert {r.server_name for r in records[:6]} == {None}
    assert not any([hasattr(r, "custom_field_1") for r in records[:6]])
    assert not any([hasattr(r, "custom_field_2") for r in records[:6]])

    # other records have the custom fields and server_name set
    assert {r.server_name for r in records[6:]} == {"DESKTOP-PJOQLJS"}
    assert all([hasattr(r, "custom_field_1") for r in records[6:]])
    assert all([hasattr(r, "custom_field_2") for r in records[6:]])

    assert {str(r.client_ip) for r in records} == {"127.0.0.1", "::1"}
    assert {r.site_name for r in records} == {None, "W3SVC1"}
    assert {r.service_status_code for r in records} == {"304", "404"}

    # check if fields with normalised names are present
    assert {str(r.cs_user_agent) for r in records} == {
        (
            "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)"
            "+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52"
        )
    }

    # check if metadata fields are present
    assert {r.log_format for r in records} == {"W3C"}
    assert {r.log_file for r in records} == {"C:/Users/John/w3c-logs/W3SVC1/u_ex211001_x.log"}
    assert {r.hostname for r in records} == {target_win.hostname}


@pytest.mark.parametrize(
    "stream, method",
    [
        (b"-, -, 10/1/2021, 00:00:00, -, \xa7, ::1, 1, 2, 3, 200, 0, GET, /, -,", "parse_iis_format_log"),
        (b"#Date: -\n#Fields: s-computername\n\xa7", "parse_w3c_format_log"),
    ],
)
def test_iis_plugin_iis_nonutf8(target_win, stream, method):
    server = iis.IISLogsPlugin(target_win)
    # should not crash on invalid bytes like \xa7
    with patch("pathlib.Path.open", new_callable=mock_open, read_data=stream):
        assert list(getattr(server, method)(Path("/iis")))[0].server_name == "\\xa7"


def test_plugins_apps_webservers_iis_access_iis_format(target_win_tzinfo, fs_win, tmpdir_name):
    config_path = absolute_path("data/webservers/iis/iis-applicationHost-iis.config")
    data_dir = absolute_path("data/webservers/iis/iis-logs-iis")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/iis-logs", data_dir)

    target_win_tzinfo.add_plugin(iis.IISLogsPlugin)

    records = list(target_win_tzinfo.iis.access())
    assert len(records) == 10
    assert records[0].ts == datetime(2021, 10, 1, 7, 19, 8, tzinfo=ZoneInfo("Pacific/Easter"))
    assert records[0].remote_ip == "127.0.0.1"
    assert records[6].remote_user is None
    assert records[0].request is None
    assert records[0].status_code == 304
    assert records[0].bytes_sent == 143
    assert records[0].referer is None
    assert records[0].useragent is None
    assert str(records[0].source) == "sysvol/Users/John/iis-logs/W3SVC1/u_in211001.log"


def test_plugins_apps_webservers_iis_access_w3c_format(target_win, fs_win, tmpdir_name):
    config_path = absolute_path("data/webservers/iis/iis-applicationHost-w3c.config")
    data_dir = absolute_path("data/webservers/iis/iis-logs-w3c")

    fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
    fs_win.map_dir("Users/John/w3c-logs", data_dir)

    target_win.add_plugin(iis.IISLogsPlugin)

    records = list(target_win.iis.access())
    assert len(records) == 20

    # W3C format type 1: does not have HTTP version or bytes_sent.
    assert records[0].ts == datetime(2021, 10, 1, 17, 12, 0, tzinfo=ZoneInfo("Etc/UTC"))
    assert records[0].remote_ip == "127.0.0.1"
    assert records[6].remote_user is None
    assert records[0].request == "GET /"
    assert records[0].status_code == 304
    assert records[0].bytes_sent == None
    assert records[0].referer is None
    assert (
        records[0].useragent
        == "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52"
    )
    assert str(records[0].source) == "C:/Users/John/w3c-logs/W3SVC1/u_ex211001_x.log"

    # W3C format type 2: contains HTTP version
    assert records[6].ts == datetime(2021, 10, 1, 17, 34, 48, tzinfo=ZoneInfo("Etc/UTC"))
    assert records[6].remote_ip == "::1"
    assert records[6].remote_user is None
    assert records[6].request == "GET / HTTP/1.1"
    assert records[6].status_code == 304
    assert records[6].bytes_sent == 143
    assert records[6].referer is None
    assert (
        records[6].useragent
        == "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52"
    )
    assert str(records[6].source) == "C:/Users/John/w3c-logs/W3SVC1/u_ex211001_x.log"

    # W3C format type 3
    assert records[11].ts == datetime(2021, 10, 1, 18, 2, 47, tzinfo=ZoneInfo("Etc/UTC"))
    assert records[11].remote_ip == "::1"
    assert records[11].remote_user is None
    assert records[11].request == "GET /another/path+path2 HTTP/1.1"
    assert records[11].status_code == 404
    assert records[11].bytes_sent == 5125
    assert records[11].referer is None
    assert (
        records[11].useragent
        == "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52"
    )
    assert str(records[11].source) == "C:/Users/John/w3c-logs/W3SVC1/u_ex211001_x.log"
