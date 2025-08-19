from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.regf.applications import (
    WindowsApplicationsPlugin,
)

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_windows_applications(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """Test if windows applications are detected correctly in the registry."""

    # Create and add a virtual hive for HKCU.
    # This is necessary because the updated plugin now searches for keys in HKEY_CURRENT_USER.
    hive_hkcu = VirtualHive()
    ntuser_path_str = "C:\\Users\\user\\NTUSER.DAT"
    ntuser_target_path = TargetPath(target_win_users.fs, ntuser_path_str)
    target_win_users.registry.add_hive(
        name="HKEY_USERS", location="HKEY_USERS\\S-0", hive=hive_hkcu, path=ntuser_target_path
    )

    # HKLM Uninstall key for Firefox
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

    # HKLM Uninstall key for Chrome, testing InstallDate format: %Y%m%d
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

    # HKLM Uninstall key for a system component with no values
    addressbook_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AddressBook"
    addressbook_key = VirtualKey(hive_hklm, addressbook_name)
    addressbook_key.timestamp = datetime(2024, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    hive_hklm.map_key(addressbook_name, addressbook_key)

    # HKLM Uninstall key for MSVC
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

    # HKLM Wow6432Node Uninstall key for 7-Zip, testing the path
    sevenzip_name = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip"
    sevenzip_key = VirtualKey(hive_hklm, sevenzip_name)
    sevenzip_key.add_value("DisplayName", "7-Zip 23.01 (x64)")
    sevenzip_key.add_value("DisplayVersion", "23.01")
    sevenzip_key.add_value("Publisher", "Igor Pavlov")
    hive_hklm.map_key(sevenzip_name, sevenzip_key)

    # HKCU Uninstall key for Notepad++, testing the path
    npp_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Notepad++"
    npp_key = VirtualKey(hive_hkcu, npp_name)
    npp_key.add_value("DisplayName", "Notepad++")
    npp_key.add_value("DisplayVersion", "8.6.4")
    npp_key.add_value("Publisher", "Notepad++ Team")
    npp_key.add_value("InstallLocation", "C:\\Program Files\\Notepad++")
    hive_hkcu.map_key(npp_name, npp_key)

    # HKLM key for testing InstallDate format: %m/%d/%Y
    vlc_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VLC"
    vlc_key = VirtualKey(hive_hklm, vlc_name)
    vlc_key.add_value("DisplayName", "VLC media player")
    vlc_key.add_value("DisplayVersion", "3.0.20")
    vlc_key.add_value("Publisher", "VideoLAN")
    vlc_key.add_value("InstallDate", "12/25/2023")  # Format: %m/%d/%Y
    hive_hklm.map_key(vlc_name, vlc_key)

    # HKLM key for testing InstallDate format: %d.%m.%Y
    gimp_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GIMP"
    gimp_key = VirtualKey(hive_hklm, gimp_name)
    gimp_key.add_value("DisplayName", "GIMP 2.10.36")
    gimp_key.add_value("DisplayVersion", "2.10.36")
    gimp_key.add_value("Publisher", "The GIMP Team")
    gimp_key.add_value("InstallDate", "15.01.2024")  # Format: %d.%m.%Y
    hive_hklm.map_key(gimp_name, gimp_key)

    # --- Execution and Assertions ---
    target_win_users.add_plugin(WindowsApplicationsPlugin)
    results = sorted(target_win_users.applications(), key=lambda r: r.name)

    assert len(results) == 8

    # 1. 7-Zip (from Wow6432Node)
    assert results[0].name == "7-Zip 23.01 (x64)"
    assert results[0].version == "23.01"
    assert results[0].author == "Igor Pavlov"
    assert results[0].ts_installed is None
    assert results[0].type == "user"

    # 2. AddressBook (system component)
    assert results[1].ts_installed is None
    assert results[1].ts_modified == datetime(2024, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert results[1].name == "AddressBook"
    assert results[1].type == "system"

    # 3. GIMP (testing date format)
    assert results[2].name == "GIMP 2.10.36"
    assert results[2].version == "2.10.36"
    assert results[2].author == "The GIMP Team"
    assert results[2].ts_installed == datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
    assert results[2].type == "user"

    # 4. Google Chrome
    assert results[3].ts_installed == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert results[3].name == "Google Chrome"
    assert results[3].version == "122.0.6261.95"
    assert results[3].author == "Google LLC"
    assert results[3].type == "user"
    assert results[3].path == "C:\\Users\\user\\Desktop\\GoogleChromeEnterpriseBundle64\\Installers\\"

    # 5. Microsoft Visual C++
    assert results[4].ts_installed == datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert results[4].name == "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532"
    assert results[4].version == "14.36.32532"
    assert results[4].author == "Microsoft Corporation"
    assert results[4].type == "system"
    assert (
        results[4].path
        == "C:\\ProgramData\\Package Cache\\{D5D19E2F-7189-42FE-8103-92CD1FA457C2}v14.36.32532\\packages\\vcRuntimeMinimum_amd64\\"  # noqa: E501
    )

    # 6. Mozilla Firefox
    assert results[5].ts_installed is None
    assert results[5].name == "Mozilla Firefox (x64 nl)"
    assert results[5].version == "123.0.1"
    assert results[5].author == "Mozilla"
    assert results[5].type == "user"
    assert results[5].path == "C:\\Program Files\\Mozilla Firefox\\firefox.exe,0"

    # 7. Notepad++ (from HKCU)
    assert results[6].name == "Notepad++"
    assert results[6].version == "8.6.4"
    assert results[6].author == "Notepad++ Team"
    assert results[6].ts_installed is None
    assert results[6].type == "user"
    assert results[6].path == "C:\\Program Files\\Notepad++"

    # 8. VLC media player (testing date format)
    assert results[7].name == "VLC media player"
    assert results[7].version == "3.0.20"
    assert results[7].author == "VideoLAN"
    assert results[7].ts_installed == datetime(2023, 12, 25, 0, 0, 0, tzinfo=timezone.utc)
    assert results[7].type == "user"
