import struct

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

UsbRegistryRecord = TargetRecordDescriptor(
    "windows/registry/usb",
    [
        ("string", "device_type"),
        ("string", "serial"),
        ("string", "vid"),
        ("string", "pid"),
        ("string", "rev"),
        ("string", "containerid"),
        ("string", "vendor"),
        ("string", "product"),
        ("string", "version"),
        ("string", "friendlyname"),
        ("datetime", "first_insert"),
        ("datetime", "first_install"),
        ("datetime", "last_insert"),
        ("datetime", "last_removal"),
        ("string", "info_origin"),
    ],
)

USB_DEVICE_PROPERTY_KEYS = {
    "first_install": ("0064", "00000064"),  # Windows 7 and higher. USB device first install date
    "first_insert": ("0065", "00000065"),  # Windows 7 and higher. USB device first insert date.
    "last_insert": ("0066", "00000066"),  # Windows 8 and higher. USB device last insert date.
    "last_removal": ("0067", "00000067"),  # Windows 8 and higer. USB device last removal date.
}


class UsbPlugin(Plugin):
    """USB plugin."""

    # USB device locations
    USB_STOR = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
    # DeviceContainers holds all USB information. Only present in windows 8 or higher
    DEVICE_CONTAINERS = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainers"
    USB = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"
    HID = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\HID"
    SCSI = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI"

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.USB_STOR))) > 0:
            raise UnsupportedPluginError(f"Registry key not found: {self.USB_STOR}")

    @internal
    def unpack_timestamps(self, usb_reg_properties):
        """
        Params:
            usb_reg_properties (Regf): A registry object with USB properties
        Returns:
            timestamps (Dict): A dict containing parsed timestamps within passed registry object
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
                else:
                    timestamps[device_property] = None
        return timestamps

    @internal
    def parse_device_name(self, device_name):
        device_info = device_name.split("&")
        device_type = device_info[0]
        vendor = device_info[1].split("Ven_")[1]
        product = device_info[2].split("Prod_")[1]
        version = None if len(device_info) < 4 else device_info[3].split("Rev_")[1]

        return dict(device_type=device_type, vendor=vendor, product=product, version=version)

    @export(record=UsbRegistryRecord)
    def usb(self):
        """Return information about attached USB devices.

        Use the registry to find information about USB devices that have been attached to the system, for example the
        HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR registry key.

        Yields UsbRegistryRecord with fields:
            hostname (string): The target hostname
            domain (string): The target domain
            type (string): Type of USB device
            serial (string): Serial number of USB storage device
            vid (string): Vendor ID of USB storage device
            pid (string): Product ID of the USB storage device
            rev (string): Version of the USB storage device
            containerid (string):
            friendlyname (string): Display name of the USB storage device
            first_insert (datetime): First insertion date of USB storage device
            first_install (datetime): First instalation date of USB storage device
            last_insert (datetime): Most recent insertion (arrival) date of USB storage device
            last_removal (datetime): Most recent removal (unplug) date of USB storage device
            info_origin (string): Location of info present in output
        """

        for k in self.target.registry.keys(self.USB_STOR):
            info_origin = "\\".join((k.path, k.name))
            usb_stor = k.subkeys()

            for usb_type in usb_stor:
                device_info = self.parse_device_name(usb_type.name)
                usb_devices = usb_type.subkeys()
                for usb_device in usb_devices:
                    properties = list(usb_device.subkeys())
                    serial = usb_device.name
                    try:
                        friendlyname = usb_device.value("FriendlyName").value
                        # NOTE: make this more gracefull, windows 10 does not have the LogConf subkey
                        timestamps = (
                            self.unpack_timestamps(properties[2])
                            if len(properties) == 3
                            else self.unpack_timestamps(properties[1])
                        )
                        # ContainerIDs can be found back in USB and WdpBusEnumRoot
                        containerid = usb_device.value("ContainerID").value
                    except RegistryValueNotFoundError:
                        friendlyname = None
                        timestamps = {
                            "first_install": None,
                            "first_insert": None,
                            "last_insert": None,
                            "last_removal": None,
                        }
                        containerid = None

                    yield UsbRegistryRecord(
                        device_type=device_info["device_type"],
                        friendlyname=friendlyname,
                        serial=serial,
                        vid=None,
                        pid=None,
                        vendor=device_info["vendor"],
                        product=device_info["product"],
                        version=device_info["version"],
                        containerid=containerid,
                        first_install=timestamps["first_install"],
                        first_insert=timestamps["first_insert"],
                        last_insert=timestamps["last_insert"],  # AKA first arrival
                        last_removal=timestamps["last_removal"],
                        info_origin=info_origin,
                        _target=self.target,
                    )
