from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


DHCPLeaseRecord = TargetRecordDescriptor(
    "macos/network/dhcp_lease",
    [
        ("datetime", "ts_lease_start"),
        ("string", "ip_address"),
        ("string", "router_ip"),
        ("string", "router_mac"),
        ("string", "ssid"),
        ("string", "network_id"),
        ("varint", "lease_length"),
        ("string", "client_id"),
        ("string", "interface"),
        ("path", "source"),
    ],
)


class MacOSDHCPPlugin(Plugin):
    """Plugin to parse macOS DHCP lease files.

    Location: /private/var/db/dhcpclient/leases/
    """

    __namespace__ = "dhcp"

    LEASE_GLOBS = [
        "private/var/db/dhcpclient/leases/*.plist",
        "var/db/dhcpclient/leases/*.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._lease_paths = []
        seen = set()
        for pattern in self.LEASE_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if path.name not in seen:
                    seen.add(path.name)
                    self._lease_paths.append(path)

    def check_compatible(self) -> None:
        if not self._lease_paths:
            raise UnsupportedPluginError("No DHCP lease files found")

    @export(record=DHCPLeaseRecord)
    def leases(self) -> Iterator[DHCPLeaseRecord]:
        """Parse DHCP lease files from /private/var/db/dhcpclient/leases/."""
        for lease_path in self._lease_paths:
            try:
                with lease_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())

                interface = lease_path.name.replace(".plist", "")

                router_mac_bytes = data.get("RouterHardwareAddress", b"")
                if isinstance(router_mac_bytes, bytes) and len(router_mac_bytes) == 6:
                    router_mac = ":".join(f"{b:02x}" for b in router_mac_bytes)
                else:
                    router_mac = str(router_mac_bytes)

                client_id_bytes = data.get("ClientIdentifier", b"")
                client_id = client_id_bytes.hex() if isinstance(client_id_bytes, bytes) else str(client_id_bytes)

                lease_start = data.get("LeaseStartDate")
                if isinstance(lease_start, datetime):
                    ts = lease_start.replace(tzinfo=timezone.utc) if lease_start.tzinfo is None else lease_start
                else:
                    ts = datetime(2001, 1, 1, tzinfo=timezone.utc)

                yield DHCPLeaseRecord(
                    ts_lease_start=ts,
                    ip_address=data.get("IPAddress", ""),
                    router_ip=data.get("RouterIPAddress", ""),
                    router_mac=router_mac,
                    ssid=data.get("SSID", ""),
                    network_id=data.get("NetworkID", ""),
                    lease_length=data.get("LeaseLength", 0),
                    client_id=client_id,
                    interface=interface,
                    source=lease_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing DHCP lease %s: %s", lease_path, e)
