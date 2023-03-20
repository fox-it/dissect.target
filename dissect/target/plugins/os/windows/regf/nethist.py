import datetime
import struct

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

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
    KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures"
    PROFILE_KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles"

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("")

    @export(record=NetworkHistoryRecord)
    def network_history(self):
        """Return attached network history.

        The HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures and
        HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles registry keys contain information
        about the networks to which the system has been connected, both wireless and wired.

        References:
            - https://www.weaklink.org/2016/11/windows-network-profile-registry-keys/
        """
        for key in self.target.registry.keys(self.KEY):
            for kind in key.subkeys():
                for sig in kind.subkeys():
                    guid = sig.value("ProfileGuid").value
                    profile = self.find_profile(guid)

                    created = parse_ts(profile.value("DateCreated").value)
                    last_connected = parse_ts(profile.value("DateLastConnected").value)

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

    def find_profile(self, guid):
        for key in self.target.registry.keys(self.PROFILE_KEY):
            try:
                return key.subkey(guid)  # Just return the first one...
            except RegistryError:
                pass


def parse_ts(val):
    items = list(struct.unpack("<8H", val))
    # If we remove the weekday (at position 2), this is a valid datetime tuple
    items.pop(2)
    return datetime.datetime(*items)
