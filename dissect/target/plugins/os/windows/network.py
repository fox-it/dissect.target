from __future__ import annotations

import re
from enum import IntEnum
from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import (
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.helpers.record import WindowsInterfaceRecord
from dissect.target.plugins.os.default.network import NetworkPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target


class IfTypes(IntEnum):
    OTHER = 1
    REGULAR_1822 = 2
    HDH_1822 = 3
    DDN_X25 = 4
    RFC877_X25 = 5
    ETHERNET_CSMACD = 6
    IS088023_CSMACD = 7
    ISO88024_TOKENBUS = 8
    ISO88025_TOKENRING = 9
    ISO88026_MAN = 10
    STARLAN = 11
    PROTEON_10MBIT = 12
    PROTEON_80MBIT = 13
    HYPERCHANNEL = 14
    FDDI = 15
    LAP_B = 16
    SDLC = 17
    DS1 = 18
    E1 = 19
    BASIC_ISDN = 20
    PRIMARY_ISDN = 21
    PROP_POINT2POINT_SERIAL = 22
    PPP = 23
    SOFTWARE_LOOPBACK = 24
    EON = 25
    ETHERNET_3MBIT = 26
    NSIP = 27
    SLIP = 28
    ULTRA = 29
    DS3 = 30
    SIP = 31
    FRAMERELAY = 32
    RS232 = 33
    PARA = 34
    ARCNET = 35
    ARCNET_PLUS = 36
    ATM = 37
    MIO_X25 = 38
    SONET = 39
    X25_PLE = 40
    ISO88022_LLC = 41
    LOCALTALK = 42
    SMDS_DXI = 43
    FRAMERELAY_SERVICE = 44
    V35 = 45
    HSSI = 46
    HIPPI = 47
    MODEM = 48
    AAL5 = 49
    SONET_PATH = 50
    SONET_VT = 51
    SMDS_ICIP = 52
    PROP_VIRTUAL = 53
    PROP_MULTIPLEXOR = 54
    IEEE80212 = 55
    FIBRECHANNEL = 56
    HIPPIINTERFACE = 57
    FRAMERELAY_INTERCONNECT = 58
    AFLANE_8023 = 59
    AFLANE_8025 = 60
    CCTEMUL = 61
    FASTETHER = 62
    ISDN = 63
    V11 = 64
    V36 = 65
    G703_64K = 66
    G703_2MB = 67
    QLLC = 68
    FASTETHER_FX = 69
    CHANNEL = 70
    IEEE80211 = 71
    IBM370PARCHAN = 72
    ESCON = 73
    DLSW = 74
    ISDN_S = 75
    ISDN_U = 76
    LAP_D = 77
    IPSWITCH = 78
    RSRB = 79
    ATM_LOGICAL = 80
    DS0 = 81
    DS0_BUNDLE = 82
    BSC = 83
    ASYNC = 84
    CNR = 85
    ISO88025R_DTR = 86
    EPLRS = 87
    ARAP = 88
    PROP_CNLS = 89
    HOSTPAD = 90
    TERMPAD = 91
    FRAMERELAY_MPI = 92
    X213 = 93
    ADSL = 94
    RADSL = 95
    SDSL = 96
    VDSL = 97
    ISO88025_CRFPRINT = 98
    MYRINET = 99
    VOICE_EM = 100
    VOICE_FXO = 101
    VOICE_FXS = 102
    VOICE_ENCAP = 103
    VOICE_OVERIP = 104
    ATM_DXI = 105
    ATM_FUNI = 106
    ATM_IMA = 107
    PPPMULTILINKBUNDLE = 108
    IPOVER_CDLC = 109
    IPOVER_CLAW = 110
    STACKTOSTACK = 111
    VIRTUALIPADDRESS = 112
    MPC = 113
    IPOVER_ATM = 114
    ISO88025_FIBER = 115
    TDLC = 116
    GIGABITETHERNET = 117
    HDLC = 118
    LAP_F = 119
    V37 = 120
    X25_MLP = 121
    X25_HUNTGROUP = 122
    TRANSPHDLC = 123
    INTERLEAVE = 124
    FAST = 125
    IP = 126
    DOCSCABLE_MACLAYER = 127
    DOCSCABLE_DOWNSTREAM = 128
    DOCSCABLE_UPSTREAM = 129
    A12MPPSWITCH = 130
    TUNNEL = 131
    COFFEE = 132
    CES = 133
    ATM_SUBINTERFACE = 134
    L2_VLAN = 135
    L3_IPVLAN = 136
    L3_IPXVLAN = 137
    DIGITALPOWERLINE = 138
    MEDIAMAILOVERIP = 139
    DTM = 140
    DCN = 141
    IPFORWARD = 142
    MSDSL = 143
    IEEE1394 = 144
    IF_GSN = 145
    DVBRCC_MACLAYER = 146
    DVBRCC_DOWNSTREAM = 147
    DVBRCC_UPSTREAM = 148
    ATM_VIRTUAL = 149
    MPLS_TUNNEL = 150
    SRP = 151
    VOICEOVERATM = 152
    VOICEOVERFRAMERELAY = 153
    IDSL = 154
    COMPOSITELINK = 155
    SS7_SIGLINK = 156
    PROP_WIRELESS_P2P = 157
    FR_FORWARD = 158
    RFC1483 = 159
    USB = 160
    IEEE8023AD_LAG = 161
    BGP_POLICY_ACCOUNTING = 162
    FRF16_MFR_BUNDLE = 163
    H323_GATEKEEPER = 164
    H323_PROXY = 165
    MPLS = 166
    MF_SIGLINK = 167
    HDSL2 = 168
    SHDSL = 169
    DS1_FDL = 170
    POS = 171
    DVB_ASI_IN = 172
    DVB_ASI_OUT = 173
    PLC = 174
    NFAS = 175
    TR008 = 176
    GR303_RDT = 177
    GR303_IDT = 178
    ISUP = 179
    PROP_DOCS_WIRELESS_MACLAYER = 180
    PROP_DOCS_WIRELESS_DOWNSTREAM = 181
    PROP_DOCS_WIRELESS_UPSTREAM = 182
    HIPERLAN2 = 183
    PROP_BWA_P2MP = 184
    SONET_OVERHEAD_CHANNEL = 185
    DIGITAL_WRAPPER_OVERHEAD_CHANNEL = 186
    AAL2 = 187
    RADIO_MAC = 188
    ATM_RADIO = 189
    IMT = 190
    MVL = 191
    REACH_DSL = 192
    FR_DLCI_ENDPT = 193
    ATM_VCI_ENDPT = 194
    OPTICAL_CHANNEL = 195
    OPTICAL_TRANSPORT = 196
    WWANPP = 243
    WWANPP2 = 244


def _try_value(subkey: RegistryKey, value: str) -> str | list | None:
    try:
        return subkey.value(value).value
    except RegistryValueNotFoundError:
        return None


def _get_config_value(key: RegistryKey, name: str, sep: str | None = None) -> set:
    value = _try_value(key, name)
    if not value or value in ("", "0.0.0.0", None, [], ["0.0.0.0"]):
        return set()
    if sep and isinstance(value, str):
        re_sep = "|".join(map(re.escape, sep))
        value = re.split(re_sep, value)
    if isinstance(value, list):
        return set(value)

    return {value}


def _construct_interface(key: RegistryKey, ip_key: str, subnet_key: str) -> set[str]:
    interface = ""

    if ip := _get_config_value(key, ip_key):
        interface = next(iter(ip))

    if not interface:
        return set()

    if subnet := _get_config_value(key, subnet_key):
        interface = f"{interface}/{next(iter(subnet))}"

    if not interface:
        return set()

    return {interface}


class WindowsNetworkPlugin(NetworkPlugin):
    """Windows network interface plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._extract_network_device_config = lru_cache(128)(self._extract_network_device_config)

    def _interfaces(self) -> Iterator[WindowsInterfaceRecord]:
        """Yields found Windows interfaces used by :meth:`NetworkPlugin.interfaces() <dissect.target.plugins.general.network.NetworkPlugin.interfaces>`."""  # noqa: E501

        # Get all the network interfaces
        for key in self.target.registry.keys(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
        ):
            for subkey in key.subkeys():
                device_info = {}

                if (net_cfg_instance_id := _try_value(subkey, "NetCfgInstanceId")) is None:
                    # if no NetCfgInstanceId is found, skip this network interface
                    continue

                # Extract the network device configuration for given interface id
                if not (config := self._extract_network_device_config(net_cfg_instance_id)):
                    continue

                # Extract a network device name for given interface id
                try:
                    name_key = self.target.registry.key(
                        f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{net_cfg_instance_id}\\Connection"
                    )
                    if value_name := _try_value(name_key, "Name"):
                        device_info["name"] = value_name
                except RegistryKeyNotFoundError:
                    pass

                # Extract the metric value from the interface registry key
                try:
                    interface_key = self.target.registry.key(
                        f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{net_cfg_instance_id}"
                    )
                    if value_metric := _try_value(interface_key, "InterfaceMetric"):
                        device_info["metric"] = value_metric
                except RegistryKeyNotFoundError:
                    pass

                # Extract the rest of the device information
                if mac_address := _try_value(subkey, "NetworkAddress"):
                    device_info["mac"] = [mac_address]
                device_info["vlan"] = _try_value(subkey, "VlanID")

                if timestamp := _try_value(subkey, "NetworkInterfaceInstallTimestamp"):
                    device_info["first_connected"] = wintimestamp(timestamp)

                if type_device := _try_value(subkey, "*IfType"):
                    device_info["type"] = IfTypes(int(type_device)).name

                # Yield a record for each non-empty configuration
                for conf in config:
                    # If no configuration is found or all configurations are empty,
                    # skip this network interface.
                    if not conf or not any(
                        [
                            conf["cidr"],
                            conf["gateway"],
                            conf["dns"],
                            conf["search_domain"],
                        ]
                    ):
                        continue

                    # Create a copy of device_info to avoid overwriting
                    record_info = device_info.copy()
                    record_info.update(conf)
                    yield WindowsInterfaceRecord(
                        **record_info,
                        source=f"HKLM\\SYSTEM\\{subkey.path}",
                        _target=self.target,
                    )

    def _extract_network_device_config(self, interface_id: str) -> list[dict[str, set | bool | None]]:
        """Extract network device configuration from the given interface_id for all ControlSets on the system."""

        dhcp_config = {
            "cidr": set(),
            "gateway": set(),
            "dns": set(),
            "search_domain": set(),
        }

        static_config = {
            "cidr": set(),
            "gateway": set(),
            "dns": set(),
            "search_domain": set(),
        }

        # Get the registry keys for the given interface id
        try:
            keys = list(
                self.target.registry.keys(
                    f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{interface_id}"
                )
            )
        except RegistryKeyNotFoundError:
            return []

        if not keys:
            return []

        for key in keys:
            # Extract DHCP configuration from the registry
            dhcp_config["cidr"].update(_construct_interface(key, "DhcpIPAddress", "DhcpSubnetMask"))
            dhcp_config["gateway"].update(_get_config_value(key, "DhcpDefaultGateway"))
            dhcp_config["dns"].update(_get_config_value(key, "DhcpNameServer", " ,"))
            dhcp_config["search_domain"].update(_get_config_value(key, "DhcpDomain"))

            # Extract static configuration from the registry
            static_config["cidr"].update(_construct_interface(key, "IPAddress", "SubnetMask"))
            static_config["gateway"].update(_get_config_value(key, "DefaultGateway"))
            static_config["dns"].update(_get_config_value(key, "NameServer", " ,"))
            static_config["search_domain"].update(_get_config_value(key, "Domain"))

        dhcp_config["enabled"] = _try_value(key, "EnableDHCP") == 1
        dhcp_config["dhcp"] = True

        static_config["enabled"] = None
        static_config["dhcp"] = False

        # Return both configurations
        return [dhcp_config, static_config]
