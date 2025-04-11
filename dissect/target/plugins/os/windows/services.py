from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import (
    RegistryError,
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

ServiceRecord = TargetRecordDescriptor(
    "windows/service",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("wstring", "displayname"),
        ("path", "servicedll"),
        ("path", "imagepath"),
        ("string", "imagepath_args"),
        ("string", "objectname"),
        ("string", "start"),
        ("string", "type"),
        ("string", "errorcontrol"),
    ],
)

SERVICE_ENUMS = {
    "Type": {
        1: "Kernel Device Driver (0x1)",
        2: "File System Driver (0x2)",
        4: "Adapter (0x4)",
        16: "Service - Own Process (0x10)",
        32: "Service - Share Process (0x20)",
    },
    "Start": {
        0: "Boot (0)",
        1: "System (1)",
        2: "Auto Start (2)",
        3: "Manual (3)",
        4: "Disabled (4)",
    },
    "ErrorControl": {
        0: "Ignore (0)",
        1: "Normal (1)",
        2: "Severe (2)",
        3: "Critical (3)",
    },
}

# Make this general, use of other plugins
RE_PATH_SPLIT = re.compile(r"([\\/][a-zA-Z0-9_\.-]+\.[a-zA-Z0-9]{3})($| )")
RE_PATH_SPLIT_FALLBACK = re.compile(r"([\\/][a-zA-Z0-9_\.-]+)($| [^a-zA-Z0-9\\/])")


class ServicesPlugin(Plugin):
    """Services plugin."""

    KEY = "HKLM\\SYSTEM\\CurrentControlSet\\Services"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("No services found in the registry")

    @export(record=ServiceRecord)
    def services(self) -> Iterator[ServiceRecord]:
        """Return information about all installed Windows services.

        The HKLM\\SYSTEM\\CurrentControlSet\\Services registry key contains information about the installed services and
        drivers on the system.

        References:
            - https://artifacts-kb.readthedocs.io/en/latest/sources/windows/ServicesAndDrivers.html

        Yields ServiceRecords with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datatime): The last modified timestamp of the registry key.
            name (string): The service name.
            displayname (string): The service display name.
            servicedll (path): The service dll.
            imagepath (path): The service image path.
            objectname (string): The object under which the service runs (for example LocalSystem)
            start (string): The service start field.
            type (string): The service type field.
            errorcontrol (string): The service error control field.
        """
        for controlset in self.target.registry.keys(self.KEY):
            for key in controlset.subkeys():
                ts = key.ts

                name = key.name
                servicedll = None

                try:
                    key.value("Type")
                except RegistryValueNotFoundError:
                    continue

                try:
                    servicedll = key.subkey("Parameters").value("ServiceDll").value
                    servicedll = self.target.fs.path(servicedll)
                except RegistryError:
                    pass

                image_path = None
                image_path_args = None

                display_name = None
                try:
                    display_name = key.value("DisplayName").value
                except RegistryValueNotFoundError:
                    pass

                object_name = None
                try:
                    object_name = key.value("ObjectName").value
                except RegistryValueNotFoundError:
                    pass

                try:
                    image_path = key.value("ImagePath").value

                    if image_path:
                        if image_path.startswith('"'):
                            p = image_path.split('"', 2)

                            image_path = p[1]
                            image_path_args = p[2].strip()
                        else:
                            m = RE_PATH_SPLIT.search(image_path)
                            if not m:
                                m = RE_PATH_SPLIT_FALLBACK.search(image_path)

                            if m:
                                image_path_args = image_path[m.end(0) :]
                                image_path = image_path[: m.end(0)].strip()
                            else:
                                pass
                        image_path = self.target.fs.path(image_path)
                except RegistryError:
                    pass

                service_control = {}
                keys = ["Start", "Type", "ErrorControl"]
                for service_information in keys:
                    try:
                        value = key.value(service_information).value
                        value = SERVICE_ENUMS[service_information].get(value)
                        attr = f"service_{service_information.lower()}"
                        service_control[attr] = value
                    except RegistryError:  # noqa: PERF203
                        pass
                err_ctr = service_control.get("service_errorcontrol")
                yield ServiceRecord(
                    ts=ts,
                    name=name,
                    displayname=display_name,
                    servicedll=servicedll,
                    imagepath=image_path,
                    imagepath_args=image_path_args,
                    objectname=object_name,
                    start=service_control.get("service_start"),
                    type=service_control.get("service_type"),
                    errorcontrol=err_ctr,
                    _target=self.target,
                )
