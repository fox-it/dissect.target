from typing import Iterator

from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import RegistryKey, RegistryValueNotFoundError
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

CamRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/cam",
    [
        ("datetime", "ts"),
        ("string", "device"),
        ("string", "app_name"),
        ("path", "path"),
        ("datetime", "last_started"),
        ("datetime", "last_stopped"),
        ("varint", "duration"),
    ],
)


class CamPlugin(Plugin):
    """Plugin that iterates various Capability Access Manager registry key locations."""

    CONSENT_STORES = [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self.app_regf_keys = self._find_apps()

    def _find_apps(self) -> list[RegistryKey]:
        apps = []
        for store in self.target.registry.keys(self.CONSENT_STORES):
            for key in store.subkeys():
                apps.append(key)

        return apps

    def check_compatible(self) -> None:
        if not self.app_regf_keys:
            raise UnsupportedPluginError("No Capability Access Manager keys found")

    def yield_apps(self) -> Iterator[RegistryKey]:
        for app in self.app_regf_keys:
            for key in app.subkeys():
                if key.name == "NonPackaged":  # NonPackaged registry key has more apps, so yield those apps
                    yield from key.subkeys()
                else:
                    yield key

    @export(record=CamRecord)
    def cam(self) -> Iterator[CamRecord]:
        """Iterate Capability Access Manager key locations.

        The Capability Access Manager keeps track of processes that access I/O devices, like the webcam or microphone.
        Applications are divided into packaged and non-packaged applications meaning Microsoft or
        non-Microsoft applications.

        References:
            - https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.capabilityaccessmanager/
            - https://svch0st.medium.com/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072

        Yields ``CamRecord`` with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The modification timestamp of the registry key.
            device (string): Name of the device privacy permission where asked for.
            app_name (string): The name of the application.
            path (path): The possible path to the application.
            last_started (datetime): When the application last started using the device.
            last_stopped (datetime): When the application last stopped using the device.
            duration (datetime): How long the application used the device (seconds).
        """

        for key in self.yield_apps():
            last_started = None
            last_stopped = None
            duration = None

            try:
                last_started = wintimestamp(key.value("LastUsedTimeStart").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStart for application: %s", key.name)

            try:
                last_stopped = wintimestamp(key.value("LastUsedTimeStop").value)
            except RegistryValueNotFoundError:
                self.target.log.warning("No LastUsedTimeStop for application: %s", key.name)

            if last_started and last_stopped:
                duration = (last_stopped - last_started).seconds

            yield CamRecord(
                ts=key.ts,
                device=key.path.split("\\")[-2],
                app_name=key.name,
                path=windows_path(key.name.replace("#", "\\")) if "#" in key.name else None,
                last_started=last_started,
                last_stopped=last_stopped,
                duration=duration,
                _target=self.target,
                _key=key,
                _user=self.target.registry.get_user(key),
            )
