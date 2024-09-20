from __future__ import annotations

from enum import IntEnum
from typing import Iterator

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import (
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.helpers.record import WindowsInterfaceRecord
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.plugins.general.network import NetworkPlugin


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


class WindowsNetworkPlugin(NetworkPlugin):
    def _interfaces(self) -> Iterator[WindowsInterfaceRecord]:
        # Get all the network interfaces
        for keys in self.target.registry.keys(
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
        ):
            for subkey in keys.subkeys():
                device_info = {}

                if (net_cfg_instance_id := _try_value(subkey, "NetCfgInstanceId")) is None:
                    # if no NetCfgInstanceId is found, skip this network interface
                    continue

                # Extract the network device configuration for given interface id
                config = self._extract_network_device_config(net_cfg_instance_id)
                if config is None or all(not conf for conf in config):
                    # if no configuration is found or all configurations are empty, skip this network interface
                    continue

                # Extract the network device name for given interface id
                name_key = self.target.registry.key(
                    f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\"
                    f"{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{net_cfg_instance_id}\\Connection"
                )
                if value_name := _try_value(name_key, "Name"):
                    device_info["name"] = value_name

                # Extract the metric value from the REGISTRY_KEY_INTERFACE key
                interface_key = self.target.registry.key(
                    f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{net_cfg_instance_id}"
                )
                if value_metric := _try_value(interface_key, "InterfaceMetric"):
                    device_info["metric"] = value_metric

                # Extract the rest of the device information
                device_info["mac"] = _try_value(subkey, "NetworkAddress")
                device_info["vlan"] = _try_value(subkey, "VlanID")

                if timestamp := _try_value(subkey, "NetworkInterfaceInstallTimestamp"):
                    device_info["first_connected"] = wintimestamp(timestamp)

                if type_device := _try_value(subkey, "*IfType"):
                    device_info["type"] = IfTypes(int(type_device)).name

                # Yield a record for each non-empty configuration
                for conf in config:
                    if conf:
                        # Create a copy of device_info to avoid overwriting
                        record_info = device_info.copy()
                        record_info.update(conf)
                        yield WindowsInterfaceRecord(
                            **record_info,
                            source=f"HKLM\\SYSTEM\\{subkey.path}",
                            _target=self.target,
                        )

    def _extract_network_device_config(
        self, interface_id: str
    ) -> list[dict[str, str | list], dict[str, str | list]] | None:
        dhcp_config = {}
        static_config = {}

        # Get the registry keys for the given interface id
        try:
            keys = self.target.registry.key(
                f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{interface_id}"
            )
        except RegistryKeyNotFoundError:
            return None

        if not len(keys):
            return None

        # Extract DHCP configuration from the registry
        dhcp_gateway = _try_value(keys, "DhcpDefaultGateway")
        if dhcp_gateway not in ["", "0.0.0.0", None, []]:
            dhcp_config["gateway"] = dhcp_gateway

        dhcp_ip = _try_value(keys, "DhcpIPAddress")
        if dhcp_ip not in ["", "0.0.0.0", None]:
            dhcp_config["ip"] = [dhcp_ip]

        dhcp_dns = _try_value(keys, "DhcpNameServer")
        if dhcp_dns not in ["", "0.0.0.0", None]:
            dhcp_config["dns"] = dhcp_dns.split(" ")

        dhcp_subnetmask = _try_value(keys, "DhcpSubnetMask")
        if dhcp_subnetmask not in ["", "0.0.0.0", None]:
            dhcp_config["subnetmask"] = [dhcp_subnetmask]

        dhcp_domain = _try_value(keys, "DhcpDomain")
        if dhcp_domain not in ["", None]:
            dhcp_config["search_domain"] = [dhcp_domain]

        if len(dhcp_config) > 0:
            dhcp_enable = _try_value(keys, "EnableDHCP")
            dhcp_config["enabled"] = dhcp_enable == 1
            dhcp_config["dhcp"] = True

        # Extract static configuration from the registry
        static_gateway = _try_value(keys, "DefaultGateway")
        if static_gateway not in ["", None, []]:
            static_config["gateway"] = static_gateway

        static_ip = _try_value(keys, "IPAddress")
        if static_ip not in ["", "0.0.0.0", ["0.0.0.0"], None, []]:
            static_config["ip"] = static_ip if isinstance(static_ip, list) else [static_ip]

        static_dns = _try_value(keys, "NameServer")
        if static_dns not in ["", "0.0.0.0", None]:
            static_config["dns"] = static_dns.split(",")

        static_subnetmask = _try_value(keys, "SubnetMask")
        if static_subnetmask not in ["", "0.0.0.0", ["0.0.0.0"], None, []]:
            static_config["subnetmask"] = (
                static_subnetmask if isinstance(static_subnetmask, list) else [static_subnetmask]
            )

        static_domain = _try_value(keys, "Domain")
        if static_domain not in ["", None]:
            static_config["search_domain"] = [static_domain]

        if len(static_config) > 0:
            static_config["enabled"] = None
            static_config["dhcp"] = False

        # Combine ip and subnetmask for extraction
        combined_configs = [
            (dhcp_config, dhcp_config.get("ip", []), dhcp_config.get("subnetmask", [])),
            (static_config, static_config.get("ip", []), static_config.get("subnetmask", [])),
        ]

        # Iterate over combined ip/subnet lists
        for config, ips, subnet_masks in combined_configs:
            for network_address in self.calculate_network(ips, subnet_masks):
                config.setdefault("network", []).append(network_address)

        # Return both configurations
        return [dhcp_config, static_config]
