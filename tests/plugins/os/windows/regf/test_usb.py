from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.usb import UsbPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_windows_usb(target_win_users: Target, hive_hklm: VirtualHive, hive_hku: VirtualHive) -> None:
    """Test discovery of windows usb connection history."""

    usbstor_name = "SYSTEM\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00"
    usbstor_key = VirtualKey(hive_hklm, usbstor_name)

    serial_name = "0401399b179e9d46555d8aa9d8618cd0a4f82512595aaea56a74bcd1c387638"
    serial_key = VirtualKey(hive_hklm, serial_name)
    serial_key.add_value(
        "ContainerID", VirtualValue(hive_hklm, "ContainerID", "{3bceaa2e-d325-5328-ba38-d55baacd43d9}")
    )
    serial_key.add_value("FriendlyName", VirtualValue(hive_hklm, "FriendlyName", "SanDisk Ultra USB Device"))
    serial_key.add_subkey("Device Parameters", VirtualKey(hive_hklm, "Device Parameters"))

    properties_key = VirtualKey(hive_hklm, "Properties")
    guid_key = VirtualKey(hive_hklm, "{83da6326-97a6-4088-9453-a1923f573b29}")

    key_0064 = VirtualKey(hive_hklm, "0064")
    key_0064.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", b"\xea\x05+$T\xdf\xda\x01"))

    key_0065 = VirtualKey(hive_hklm, "0065")
    key_0065.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", b"\xea\x05+$T\xdf\xda\x01"))

    key_0066 = VirtualKey(hive_hklm, "0066")
    key_0066.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", b"\xea\x05+$T\xdf\xda\x01"))

    key_0067 = VirtualKey(hive_hklm, "0067")
    key_0067.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", b"\x8b\xe0\x10\x96T\xdf\xda\x01"))

    guid_key.add_subkey("0064", key_0064)
    guid_key.add_subkey("0065", key_0065)
    guid_key.add_subkey("0066", key_0066)
    guid_key.add_subkey("0067", key_0067)
    properties_key.add_subkey("{83da6326-97a6-4088-9453-a1923f573b29}", guid_key)
    serial_key.add_subkey("Properties", properties_key)
    usbstor_key.add_subkey(serial_name, serial_key)
    hive_hklm.map_key(usbstor_name, usbstor_key)

    mounted_devices = VirtualKey(hive_hklm, "SYSTEM\\MountedDevices")
    mounted_devices.add_value(
        "\\DosDevices\\E:", VirtualValue(hive_hklm, "\\DosDevices\\E:", serial_name.encode("utf-16-le"))
    )
    mounted_devices.add_value(
        "\\??\\Volume{4be8862a-4b47-11ef-9a61-70d823df2914}",
        VirtualValue(hive_hklm, "\\??\\Volume{4be8862a-4b47-11ef-9a61-70d823df2914}", serial_name.encode("utf-16-le")),
    )
    hive_hklm.map_key("SYSTEM\\MountedDevices", mounted_devices)

    mounted_volumes_name = "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices\\SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00#0401399B179E9D46555D8AA9D8618CD0A4F82512595AAEA56A74BCD1C387638#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}"  # noqa: E501
    mounted_volumes = VirtualKey(hive_hklm, mounted_volumes_name)
    mounted_volumes.add_value("FriendlyName", VirtualValue(hive_hklm, "FriendlyName", "Example USB"))
    hive_hklm.map_key(mounted_volumes_name, mounted_volumes)

    mountpoints2_name = (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Mountpoints2\\{4be8862a-4b47-11ef-9a61-70d823df2914}"
    )
    mountpoints2 = VirtualKey(hive_hku, mountpoints2_name)
    hive_hku.map_key(mountpoints2_name, mountpoints2)

    target_win_users.add_plugin(UsbPlugin)

    with patch("dissect.target.plugins.os.windows.registry.RegistryPlugin.get_user_details") as mock_reg_user_details:
        mock_reg_user_details.return_value = target_win_users.user_details.find(username="John")
        results = list(target_win_users.usb())

    assert len(results) == 1
    assert results[0].type == "Disk"
    assert results[0].serial == "0401399b179e9d46555d8aa9d8618cd0a4f82512595aaea56a74bcd1c387638"
    assert results[0].container_id == "{3bceaa2e-d325-5328-ba38-d55baacd43d9}"
    assert results[0].vendor == "SanDisk"
    assert results[0].product == "Ultra"
    assert results[0].revision == "1.00"
    assert results[0].friendly_name == "SanDisk Ultra USB Device"
    assert results[0].first_insert == dt("2024-07-26 12:05:43.789719+00:00")
    assert results[0].first_install == dt("2024-07-26 12:05:43.789719+00:00")
    assert results[0].last_insert == dt("2024-07-26 12:05:43.789719+00:00")
    assert results[0].last_removal == dt("2024-07-26 12:08:54.878632+00:00")
    assert results[0].volumes == ["Example USB"]
    assert results[0].mounts == ["E:", "\\??\\Volume{4be8862a-4b47-11ef-9a61-70d823df2914}"]
    assert results[0].users == ["John"]
    assert results[0].source == "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
