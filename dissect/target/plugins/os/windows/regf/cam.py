from typing import Iterator

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import (
    RegfKey,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

CamRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/cam",
    [
        ("string", "device"),
        ("string", "app_name"),
        ("datetime", "last_started"),
        ("datetime", "last_stopped"),
    ],
)


class CamPlugin(Plugin):
    """Plugin that iterates various Capability Access Manager registry key locations."""

    CONSENT_STORE = "{}\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
    KEYS = []

    def __init__(self, target: Target):
        super().__init__(target)
        for key in target.registry.keys("HKU\\"):
            if not key.subkeys():
                continue

            for subkey in key.subkeys():
                hku_base = f"HKU\\{subkey.name}"

                try:
                    for k in target.registry.key(self.CONSENT_STORE.format(hku_base)).subkeys():
                        full_key_path = f"{hku_base}\\{k.path}"
                        self.KEYS.append(full_key_path)
                except RegistryKeyNotFoundError:
                    pass

                try:
                    for k in target.registry.key(self.CONSENT_STORE.format("HKLM")).subkeys():
                        full_key_path = (
                            f"HKLM\\Software\\{k.path}"  # For some reason "Software" disappears so added it here
                        )
                        self.KEYS.append(full_key_path)
                except RegistryKeyNotFoundError:
                    pass

    def check_compatible(self) -> None:
        if not len(list(self.KEYS)):
            raise UnsupportedPluginError("No Capability Access Manager keys found")

    def yield_apps(self) -> Iterator[RegfKey]:
        for base_key in self.KEYS:
            for key in self.target.registry.keys(base_key):
                if application_keys := key.subkeys():
                    for app in application_keys:
                        if "NonPackaged" in app.name:  # NonPackaged registry key has more apps, so yield those apps
                            yield from app.subkeys()

                        yield app

    @export(record=CamRecord)
    def cam(self) -> Iterator[CamRecord]:
        """Iterate Capability Access Manager key locations.

        The Capability Access Manager keeps track of processes that access I/O devices, like the webcam or microphone.
        Applications are divided into packaged and non-packaged applications meaning Microsoft or
        non-Microsoft applications.

        References:
            - https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/
            - https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

        Yields Cam records with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            app_name (string): The name of the application.
            last_started (datetime): When the application last started using the device.
            last_stopped (datetime): When the application last stopped using the device.
        """

        for key in self.yield_apps():
            last_started = None
            last_stopped = None
            app_name = key.name.rsplit("\\", 1)[0]
            app_name = app_name.replace("#", "\\")
            device = key.path.split("\\")[-2]

            try:
                last_started = wintimestamp(key.value("LastUsedTimeStart").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStart for application: %s", key.name)
                pass

            try:
                last_stopped = wintimestamp(key.value("LastUsedTimeStop").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStop for application: %s", key.name)
                pass

            yield CamRecord(
                device=device,
                app_name=app_name,
                last_started=last_started,
                last_stopped=last_stopped,
                _target=self.target,
                _key=key,
                _user=self.target.registry.get_user(key),
            )
