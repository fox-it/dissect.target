from datetime import datetime, timezone

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.regf.applications import (
    WindowsApplicationsPlugin,
)
from dissect.target.target import Target


def test_windows_applications(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """test if windows applications are detected correctly in the registry"""

    firefox_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox 123.0.1 (x64 nl)"
    firefox_key = VirtualKey(hive_hklm, firefox_name)
    firefox_key.add_value("Comments", "Mozilla Firefox 123.0.1 (x64 nl)")
    firefox_key.add_value("DisplayIcon", "C:\\Program Files\\Mozilla Firefox\\firefox.exe,0")
    firefox_key.add_value("DisplayName", "Mozilla Firefox (x64 nl)")
    firefox_key.add_value("DisplayVersion", "123.0.1")
    firefox_key.add_value("EstimatedSize", 238271)
    firefox_key.add_value("HelpLink", "https://support.mozilla.org")
    firefox_key.add_value("InstallLocation", "C:\\Program Files\\Mozilla Firefox")
    firefox_key.add_value("NoModify", 1)
    firefox_key.add_value("NoRepair", 1)
    firefox_key.add_value("Publisher", "Mozilla")
    firefox_key.add_value("URLInfoAbout", "https://www.mozilla.org")
    firefox_key.add_value("URLUpdateInfo", "https://www.mozilla.org/firefox/123.0.1/releasenotes")
    firefox_key.add_value("UninstallString", '"C:\\Program Files\\Mozilla Firefox\\uninstall\\helper.exe"')
    hive_hklm.map_key(firefox_name, firefox_key)

    chrome_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{47FB91DD-98F3-3C87-A963-357B14EAC7C9}"
    chrome_key = VirtualKey(hive_hklm, chrome_name)
    chrome_key.add_value("DisplayVersion", "122.0.6261.95")
    chrome_key.add_value("InstallDate", "20240301")
    chrome_key.add_value("InstallLocation", "")
    chrome_key.add_value("InstallSource", "C:\\Users\\user\\Desktop\\GoogleChromeEnterpriseBundle64\\Installers\\")
    chrome_key.add_value("ModifyPath", "MsiExec.exe /X{47FB91DD-98F3-3C87-A963-357B14EAC7C9}")
    chrome_key.add_value("NoModify", 1)
    chrome_key.add_value("Publisher", "Google LLC")
    chrome_key.add_value("EstimatedSize", 113725)
    chrome_key.add_value("UninstallString", "MsiExec.exe /X{47FB91DD-98F3-3C87-A963-357B14EAC7C9}")
    chrome_key.add_value("VersionMajor", 70)
    chrome_key.add_value("VersionMinor", 29)
    chrome_key.add_value("WindowsInstaller", 1)
    chrome_key.add_value("Version", 1176322143)
    chrome_key.add_value("Language", 1033)
    chrome_key.add_value("DisplayName", "Google Chrome")
    hive_hklm.map_key(chrome_name, chrome_key)

    target_win_users.add_plugin(WindowsApplicationsPlugin)
    results = sorted(list(target_win_users.applications()), key=lambda r: r.name)

    assert len(results) == 2

    assert results[0].ts_installed == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert results[0].name == "Google Chrome"
    assert results[0].version == "122.0.6261.95"
    assert results[0].author == "Google LLC"
    assert results[0].type == "user"
    assert results[0].path == "C:\\Users\\user\\Desktop\\GoogleChromeEnterpriseBundle64\\Installers\\"

    assert results[0].ts_installed is None
    assert results[0].name == "Mozilla Firefox (x64 nl)"
    assert results[0].version == "123.0.1"
    assert results[0].author == "Mozilla"
    assert results[0].type == "user"
    assert results[0].path == "C:\\Program Files\\Mozilla Firefox\\firefox.exe,0"
