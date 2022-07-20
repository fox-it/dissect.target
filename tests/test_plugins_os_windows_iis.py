from dissect.target.plugins.os.windows import iis

from ._utils import absolute_path


def test_iis_plugin_iis_format(target_win, fs_win, tmpdir_name):

    config_path = absolute_path("data/iis-applicationHost-iis.config")
    data_dir = absolute_path("data/iis-logs-iis")

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

    config_path = absolute_path("data/iis-applicationHost-w3c.config")
    data_dir = absolute_path("data/iis-logs-w3c")

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
