from __future__ import annotations

import re
import struct
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import (
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import VirtualKey

UsbRegistryRecord = TargetRecordDescriptor(
    "windows/registry/usb",
    [
        ("string", "type"),
        ("string", "serial"),
        ("string", "container_id"),
        ("string", "vendor"),
        ("string", "product"),
        ("string", "revision"),
        ("string", "friendly_name"),
        ("datetime", "first_insert"),
        ("datetime", "first_install"),
        ("datetime", "last_insert"),
        ("datetime", "last_removal"),
        ("string[]", "volumes"),
        ("string[]", "mounts"),
        ("string[]", "users"),
        ("path", "source"),
    ],
)

USB_DEVICE_PROPERTY_KEYS = {
    "first_install": ("0064", "00000064"),  # Windows 7 and higher. USB device first install date
    "first_insert": ("0065", "00000065"),  # Windows 7 and higher. USB device first insert date.
    "last_insert": ("0066", "00000066"),  # Windows 8 and higher. USB device last insert date.
    "last_removal": ("0067", "00000067"),  # Windows 8 and higer. USB device last removal date.
}

RE_DEVICE_NAME = re.compile(r"^(?P<type>.+?)&Ven_(?P<vendor>.+?)&Prod_(?P<product>.+?)(&Rev_(?P<revision>.+?))?$")


class UsbPlugin(Plugin):
    """Windows USB history plugin.

    Parses Windows registry data about attached USB devices. Does not parse EVTX EventIDs
    or ``C:\\Windows\\inf\\setupapi(.dev).log``.

    To get a full picture of the USB history on a Windows machine, you should parse the
    relevant EventIDs using the evtx plugin. For more research on event log USB forensics, see:

        - https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10
        - https://dfir.pubpub.org/pub/h78di10n/release/2
        - https://www.senturean.com/posts/19_08_03_usb_storage_forensics_1/#1-system-events

    Resources:
        - https://hatsoffsecurity.com/2014/06/05/usb-forensics-pt-1-serial-number/
        - http://www.swiftforensics.com/2013/11/windows-8-new-registry-artifacts-part-1.html
        - https://www.sans.org/blog/the-truth-about-usb-device-serial-numbers/
    """

    # Stores history of mounted USB devices
    USB_STOR = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"

    # Stores the relation between a USB container_id and the FriendlyName of mounted volume(s) (Windows 7 and up)
    PORTABLE_DEVICES = "HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"

    # Stores the most recent mapping of a mount letter and a container_id
    MOUNT_LETTER_MAP = "HKLM\\SYSTEM\\MountedDevices"

    # User history of mount points accesses in explorer.exe
    USER_MOUNTS = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Mountpoints2"

    # Other artifacts we currently do not parse:
    # - "sysvol\Windows\inf\setupapi(.dev).log"
    # - "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"
    # - "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\HID"
    # - "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI"
    # - "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainers"
    # - "SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt"

    def check_compatible(self) -> None:
        if not list(self.target.registry.keys(self.USB_STOR)):
            raise UnsupportedPluginError(f"Registry key not found: {self.USB_STOR}")

    @export(record=UsbRegistryRecord)
    def usb(self) -> Iterator[UsbRegistryRecord]:
        """Yields information about (historically) attached USB storage devices on Windows.

        Uses the registry to find information about USB storage devices that have been attached to the system.
        Also tries to find the past volume name and mount letters of the USB device and what user(s) interacted
        with them using ``explorer.exe``.
        """

        for key in self.target.registry.keys(self.USB_STOR):
            for usb_type in key.subkeys():
                try:
                    device_info = parse_device_name(usb_type.name)
                except ValueError:
                    self.target.log.warning("Unable to parse USB device name: %s", usb_type.name)
                    device_info = {"type": None, "vendor": None, "product": None, "revision": None}

                for usb_device in usb_type.subkeys():
                    serial = usb_device.name
                    friendly_name = None
                    container_id = None
                    timestamps = {
                        "first_install": None,
                        "first_insert": None,
                        "last_insert": None,
                        "last_removal": None,
                    }

                    try:
                        friendly_name = usb_device.value("FriendlyName").value
                    except RegistryValueNotFoundError:
                        self.target.log.warning("No FriendlyName for USB with serial: %s", serial)

                    try:
                        container_id = usb_device.value("ContainerID").value
                    except RegistryValueNotFoundError:
                        self.target.log.warning("No ContainerID for USB with serial: %s", serial)

                    try:
                        timestamps = unpack_timestamps(usb_device.subkey("Properties"))
                    except RegistryValueNotFoundError as e:
                        self.target.log.warning("Unable to parse USBSTOR registry properties for serial: %s", serial)
                        self.target.log.debug("", exc_info=e)

                    # We can check if any HKCU hive(s) are populated with the Volume GUID of the USB storage device.
                    # If a user has interacted with the mounted volume using explorer.exe we will get a match.
                    volumes = list(self.find_volumes(serial))
                    mounts = list(self.find_mounts(serial))
                    users = [
                        u.user.name for u in self.find_users([m[10:] for m in mounts if m.startswith("\\??\\Volume{")])
                    ]

                    yield UsbRegistryRecord(
                        friendly_name=friendly_name,
                        serial=serial,
                        container_id=container_id,
                        **device_info,
                        **timestamps,
                        volumes=volumes,
                        mounts=mounts,
                        users=users,
                        source=self.USB_STOR,
                        _target=self.target,
                    )

    def find_volumes(self, serial: str) -> Iterator[str]:
        """Attempts to find mounted volume names for the given serial."""
        serial = serial.lower()
        try:
            for device in self.target.registry.key(self.PORTABLE_DEVICES).subkeys():
                if serial in device.name.lower():
                    yield device.value("FriendlyName").value
        except RegistryKeyNotFoundError:
            pass

    def find_mounts(self, serial: str) -> Iterator[str]:
        """Attempts to find drive letters the given serial has been mounted on."""
        serial = serial.lower()
        try:
            for mount in self.target.registry.key(self.MOUNT_LETTER_MAP).values():
                try:
                    if serial in mount.value.decode("utf-16-le").lower():
                        yield mount.name.replace("\\DosDevices\\", "")
                except UnicodeDecodeError:  # noqa: PERF203
                    pass
        except RegistryKeyNotFoundError:
            pass

    def find_users(self, volume_guids: list[str]) -> Iterator[str]:
        """Attempt to find Windows users that have interacted with the given volume GUIDs."""

        for volume_guid in volume_guids:
            try:
                for key in self.target.registry.key(self.USER_MOUNTS + "\\" + volume_guid):
                    yield self.target.registry.get_user_details(key)
            except RegistryKeyNotFoundError:  # noqa: PERF203
                pass


def unpack_timestamps(usb_reg_properties: VirtualKey) -> dict[str, int]:
    """Unpack relevant Windows timestamps from the provided USB registry properties subkey.

    Args:
        usb_reg_properties: A registry object with USB properties.

    Returns:
        A dict containing parsed timestamps within passed registry object.
    """

    usb_reg_properties = usb_reg_properties.subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
    timestamps = {}

    for device_property, usbstor_values in USB_DEVICE_PROPERTY_KEYS.items():
        for usb_val in usbstor_values:
            if usb_val in [x.name for x in usb_reg_properties.subkeys()]:
                version_key = usb_reg_properties.subkey(usb_val)
                if "00000000" in version_key.subkeys():
                    data_value = version_key.subkey("00000000").value("Data").value
                else:
                    data_value = version_key.value("(Default)").value
                timestamps[device_property] = wintimestamp(struct.unpack("<Q", data_value)[0])
                break
            timestamps[device_property] = None
    return timestamps


def parse_device_name(device_name: str) -> dict[str, str]:
    """Parse a registry device name into components."""

    match = RE_DEVICE_NAME.match(device_name)
    if not match:
        raise ValueError(f"Unable to parse USB device name: {device_name}")

    return match.groupdict()
