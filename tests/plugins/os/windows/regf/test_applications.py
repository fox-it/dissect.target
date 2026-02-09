from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.regf.applications import (
    WindowsApplicationsPlugin,
)

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_windows_applications(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """Test if windows applications are detected correctly in the registry."""

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

    addressbook_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AddressBook"
    addressbook_key = VirtualKey(hive_hklm, addressbook_name)
    addressbook_key.timestamp = datetime(2024, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    hive_hklm.map_key(addressbook_name, addressbook_key)

    msvc_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{D5D19E2F-7189-42FE-8103-92CD1FA457C2}"
    msvc_key = VirtualKey(hive_hklm, msvc_name)
    msvc_key.add_value("DisplayName", "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532")
    msvc_key.add_value("InstallDate", "20240301")
    msvc_key.add_value("DisplayVersion", "14.36.32532")
    msvc_key.add_value("Publisher", "Microsoft Corporation")
    msvc_key.add_value(
        "InstallSource",
        "C:\\ProgramData\\Package Cache\\{D5D19E2F-7189-42FE-8103-92CD1FA457C2}v14.36.32532\\packages\\vcRuntimeMinimum_amd64\\",  # noqa: E501
    )
    msvc_key.add_value("SystemComponent", 1)
    hive_hklm.map_key(msvc_name, msvc_key)

    target_win_users.add_plugin(WindowsApplicationsPlugin)
    results = sorted(target_win_users.applications(), key=lambda r: r.name)

    assert len(results) == 4

    assert results[0].ts_installed is None
    assert results[0].ts_modified == datetime(2024, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert results[0].name == "AddressBook"
    assert results[0].type == "system"

    assert results[1].ts_installed == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert results[1].name == "Google Chrome"
    assert results[1].version == "122.0.6261.95"
    assert results[1].author == "Google LLC"
    assert results[1].type == "user"
    assert results[1].path == "C:\\Users\\user\\Desktop\\GoogleChromeEnterpriseBundle64\\Installers\\"

    assert results[2].ts_installed == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert results[2].name == "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532"
    assert results[2].version == "14.36.32532"
    assert results[2].author == "Microsoft Corporation"
    assert results[2].type == "system"
    assert (
        results[2].path
        == "C:\\ProgramData\\Package Cache\\{D5D19E2F-7189-42FE-8103-92CD1FA457C2}v14.36.32532\\packages\\vcRuntimeMinimum_amd64\\"  # noqa: E501
    )

    assert results[3].ts_installed is None
    assert results[3].name == "Mozilla Firefox (x64 nl)"
    assert results[3].version == "123.0.1"
    assert results[3].author == "Mozilla"
    assert results[3].type == "user"
    assert results[3].path == "C:\\Program Files\\Mozilla Firefox\\firefox.exe,0"
