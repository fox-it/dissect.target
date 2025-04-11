from __future__ import annotations

import io
from typing import TYPE_CHECKING

from dissect.target.helpers import fsutil
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.apps.productivity.msoffice import MSOffice

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_office_startup_default_machine(
    target_win_users: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive
) -> None:
    """Test if machine-scoped startup items are found in default locations."""

    office_install_path = "C:/Office"
    key_path = "Software\\Microsoft\\Office\\16.0\\Word\\InstallRoot"
    startup_item_path = fsutil.join(office_install_path, "STARTUP/plugin.wll")

    install_root_key = VirtualKey(hive_hklm, key_path)
    install_root_key.add_value("Path", office_install_path)
    hive_hklm.map_key(key_path, install_root_key)
    fs_win.map_file_fh(startup_item_path.removeprefix("C:/"), io.BytesIO(b"Plugin Data"))

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.startup())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.path == startup_item_path
    assert item.creation_time == target_win_users.fs.stat(startup_item_path).st_birthtime


def test_office_startup_default_user(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if user-scoped startup items are found in default locations."""

    startup_item_path = "C:/Users/John/AppData/Roaming/Microsoft/Templates/normal.dotx"
    fs_win.map_file_fh(startup_item_path.removeprefix("C:/"), io.BytesIO(b"Template Data"))

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.startup())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.path == startup_item_path
    assert item.creation_time == target_win_users.fs.stat(startup_item_path).st_birthtime


def test_office_startup_options(target_win_users: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive) -> None:
    """Test if startup items are found in custom specified locations."""

    startup_item_path = "C:/FUNWAREZ/innocent.dll"
    key_path = "Software\\Microsoft\\Office\\16.0\\Word\\Options"

    custom_startup_key = VirtualKey(hive_hklm, key_path)
    custom_startup_key.add_value("STARTUP-PATH", "C:/FUNWAREZ")
    hive_hklm.map_key(key_path, custom_startup_key)
    fs_win.map_file_fh(startup_item_path.removeprefix("C:/"), io.BytesIO(b"Exploit Data"))

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.startup())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.path == startup_item_path
    assert item.creation_time == target_win_users.fs.stat(startup_item_path).st_birthtime


def test_office_com_addin(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """Test if COM add-ins are found."""

    addin_prog_id = "ExcelAddin"
    addin_key_path = f"Software\\Microsoft\\Office\\Excel\\Addins\\{addin_prog_id}"
    cls_id = "{ADC6CB82-424C-11D2-952A-00C04FA34F05}"

    addin_key = VirtualKey(hive_hklm, addin_key_path)
    addin_key.add_value("FriendlyName", "An Excel com addin")
    addin_key.add_value("LoadBehavior", 3)
    hive_hklm.map_key(addin_key_path, addin_key)
    hive_hklm.map_value(f"Software\\Classes\\{addin_prog_id}\\CLSID", "(Default)", cls_id)
    hive_hklm.map_value(f"Software\\Classes\\CLSID\\{cls_id}\\InprocServer32", "(Default)", "c:\\payload.exe")

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.native())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.name == "An Excel com addin"
    assert item.type == "com"
    assert item.load_behavior == "Autostart"
    assert item.codebases == ["c:\\payload.exe"]


def test_office_vsto_addin(target_win_users: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive) -> None:
    """Test if vsto add-ins are found."""

    addin_prog_id = "ExcelAddin"
    addin_key_path = f"Software\\Microsoft\\Office\\Excel\\Addins\\{addin_prog_id}"

    fs_win.map_dir("vsto", "tests/_data/plugins/apps/productivity/vsto")
    addin_key = VirtualKey(hive_hklm, addin_key_path)
    addin_key.add_value("FriendlyName", "An Excel vsto addin")
    addin_key.add_value("LoadBehavior", 2)
    addin_key.add_value("Manifest", "c:\\vsto\\MicrosoftDataStreamerforExcel.vsto|vstolocal")
    hive_hklm.map_key(addin_key_path, addin_key)

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.native())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.name == "An Excel vsto addin"
    assert item.type == "vsto"
    assert item.load_behavior == "Autostart"
    assert not item.loaded
    assert item.manifest == "c:\\vsto\\MicrosoftDataStreamerforExcel.vsto|vstolocal"
    assert item.codebases == ["c:\\vsto\\MicrosoftDataStreamerforExcel.dll"]


def test_office_web_addin(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if web add-ins are found."""

    fs_win.map_dir("users/John/AppData/local/Microsoft/Office/16.0/Wef", "tests/_data/plugins/apps/productivity/wef")

    office_plugin = MSOffice(target_win_users)
    startup_items = list(office_plugin.web())

    assert len(startup_items) == 1
    item, *_ = startup_items
    assert item.name == "ChatGPT for MS Word"
    assert item.provider_name == "Apps Do Wonders LLC"
    assert (
        item.manifest == "C:\\Users\\John\\AppData\\local\\Microsoft\\Office\\16.0\\Wef\\Manifests\\wa200007708_1.0.0.0"
    )
    assert item.source_locations == ["https://word-addin.appsdowonders.com/taskpane.html"]
    assert item.version == "1.0.0.0"
