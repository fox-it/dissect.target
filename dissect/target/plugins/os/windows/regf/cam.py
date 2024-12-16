from typing import Iterator

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import RegfKey, RegistryValueNotFoundError
from dissect.target.plugin import Plugin, export

CamRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/cam",
    [
        ("datetime", "ts"),
        ("string", "app_name"),
        ("datetime", "last_used_time_start"),
        ("datetime", "last_used_time_stop"),
    ],
)


class CamPlugin(Plugin):
    """Plugin that iterates various Capability Access Manager registry key locations."""

    BASE_KEY = "{}\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{}"
    DB_LOCATION = "sysvol/ProgramData/Microsoft/Windows/CapabilityAccessManager/CapabilityAccessManager.db"
    KEYS = []

    def set_keys(self):
        for key in self.target.registry.keys("HKU\\"):
            if not key.subkeys():
                continue

            for subkey in key.subkeys():
                for resource in ["webcam", "microphone"]:
                    self.KEYS.append(self.BASE_KEY.format(f"HKU\\{subkey.name}", resource))
                    self.KEYS.append(self.BASE_KEY.format("HKLM", resource))

    def check_compatible(self) -> None:
        self.set_keys()
        if not len(list(self.target.registry.keys(self.KEYS))):
            raise UnsupportedPluginError("No Capability Access Manager keys found")

    def yield_apps(self) -> Iterator[RegfKey]:
        for base_key in self.KEYS:
            for key in self.target.registry.keys(base_key):
                application_keys = key.subkeys()

                if not application_keys:
                    continue

                for app in application_keys:
                    if "NonPackaged" in app.name:  # NonPackaged registry key has more apps, so yield those apps
                        yield from app.subkeys()

                    yield app

    @export(record=CamRecord)
    def cam(self) -> Iterator[CamRecord]:
        """Iterate Capability Access Manager key locations. See source for all locations.

        The Capability Access Manager keeps track of processes that access I/O like devices,
        like the webcam or microphone of a machine. This information is stored in registry.
        Applications are divided into packaged and non-packaged applications meaning
        Microsoft or non-Microsoft applications.

        References:
            - https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/
            - https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

        Yields Capability Access Manager keys with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified timestamp.
            app_name (string): The name of the application.
            last_used_time_start (datetime): When the app last started using the microphone/webcam.
            last_used_time_start (datetime): When the app last stopped using the microphone/webcam.
        """

        for key in self.yield_apps():
            try:
                last_used_time_start = wintimestamp(key.value("LastUsedTimeStart").value)
                last_used_time_stop = wintimestamp(key.value("LastUsedTimeStop").value)
            except RegistryValueNotFoundError:
                continue

            app_name = key.name.rsplit("\\", 1)[0]
            app_name = app_name.replace("#", "\\")

            yield CamRecord(
                ts=key.timestamp,
                app_name=app_name,
                last_used_time_start=last_used_time_start,
                last_used_time_stop=last_used_time_stop,
                _target=self.target,
                _key=key,
                _user=self.target.registry.get_user(key),
            )
