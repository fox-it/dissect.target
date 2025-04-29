from __future__ import annotations

import datetime
import struct
from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey

NetworkHistoryRecord = TargetRecordDescriptor(
    "windows/registry/nethist",
    [
        ("datetime", "created"),
        ("datetime", "last_connected"),
        ("string", "profile_guid"),
        ("string", "profile_name"),
        ("string", "description"),
        ("string", "dns_suffix"),
        ("string", "first_network"),
        ("string", "default_gateway_mac"),
        ("string", "signature"),
    ],
)


class NethistPlugin(Plugin):
    """Windows network history plugin."""

    KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures"
    PROFILE_KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("No Networklist registry keys found")

    @export(record=NetworkHistoryRecord)
    def network_history(self) -> Iterator[NetworkHistoryRecord]:
        """Return attached network history.

        The HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures and
        HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles registry keys contain information
        about the networks to which the system has been connected, both wireless and wired.

        References:
            - https://web.archive.org/web/20221127181357/https://www.weaklink.org/2016/11/windows-network-profile-registry-keys/
        """
        target_tz = self.target.datetime.tzinfo

        for key in self.target.registry.keys(self.KEY):
            for kind in key.subkeys():
                for sig in kind.subkeys():
                    guid = sig.value("ProfileGuid").value
                    profile = self.find_profile(guid)

                    created = parse_ts(profile.value("DateCreated").value, tzinfo=target_tz)
                    last_connected = parse_ts(profile.value("DateLastConnected").value, tzinfo=target_tz)

                    yield NetworkHistoryRecord(
                        created=created,
                        last_connected=last_connected,
                        profile_guid=guid,
                        profile_name=profile.value("ProfileName").value,
                        description=sig.value("Description").value,
                        dns_suffix=sig.value("DnsSuffix").value,
                        first_network=sig.value("FirstNetwork").value,
                        default_gateway_mac=sig.value("DefaultGatewayMac").value.hex(),
                        signature=sig.name,
                        _target=self.target,
                    )

    def find_profile(self, guid: str) -> RegistryKey | None:
        for key in self.target.registry.keys(self.PROFILE_KEY):
            try:
                return key.subkey(guid)  # Just return the first one...
            except RegistryError:  # noqa: PERF203
                pass
        return None


def parse_ts(val: bytes, tzinfo: datetime.tzinfo = datetime.timezone.utc) -> datetime.datetime:
    items = list(struct.unpack("<8H", val))
    # If we remove the weekday (at position 2), this is a valid datetime tuple
    items.pop(2)
    return datetime.datetime(*items, tzinfo=tzinfo)
