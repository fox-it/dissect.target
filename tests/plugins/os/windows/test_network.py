from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from dissect.target.target import Target


@dataclass
class MockRegVal:
    name: str
    value: str | int


REGISTRY_KEY_INTERFACE = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
REGISTRY_KEY_CONTROLSET = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
REGISTRY_KEY_CONNECTION = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"


@pytest.mark.parametrize(
    "mock_values, expected_values",
    [
        (
            {
                "VlanID": 12,
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 1,
                "NetworkAddress": "DE:AD:BE:EF:DE:AD",
                "NetworkInterfaceInstallTimestamp": 130005216000000000,
                "DhcpDefaultGateway": ["10.10.10.1"],
                "DhcpIPAddress": "10.10.10.10",
                "DhcpNameServer": "10.10.10.2",
                "DhcpSubnetMask": "255.255.255.0",
                "InterfaceMetric": 15,
                "DhcpDomain": "work",
                "Name": "ETHERNET 0",
                "EnableDHCP": 1,
            },
            {
                "ip": ["10.10.10.10"],
                "dns": ["10.10.10.2"],
                "gateway": ["10.10.10.1"],
                "mac": ["DE:AD:BE:EF:DE:AD"],
                "network": ["10.10.10.0/24"],
                "subnetmask": ["255.255.255.0"],
                "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                "type": "OTHER",
                "vlan": 12,
                "name": "ETHERNET 0",
                "search_domain": ["work"],
                "metric": 15,
                "dhcp": True,
                "enabled": True,
            },
        ),
        (
            {
                "VlanID": 11,
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 6,
                "NetworkAddress": "DE:AD:BE:EF:DE:AD",
                "NetworkInterfaceInstallTimestamp": 130005216000000000,
                "DefaultGateway": ["10.10.10.1"],
                "IPAddress": "10.10.10.10",
                "NameServer": "10.10.10.2",
                "SubnetMask": "255.255.255.0",
                "InterfaceMetric": 5,
                "Domain": "local",
                "EnableDHCP": 0,
            },
            {
                "ip": ["10.10.10.10"],
                "dns": ["10.10.10.2"],
                "gateway": ["10.10.10.1"],
                "mac": ["DE:AD:BE:EF:DE:AD"],
                "subnetmask": ["255.255.255.0"],
                "network": ["10.10.10.0/24"],
                "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                "type": "ETHERNET_CSMACD",
                "vlan": 11,
                "name": None,
                "search_domain": ["local"],
                "metric": 5,
                "dhcp": False,
                "enabled": None,
            },
        ),
        (
            {
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 1,
                "DefaultGateway": ["10.10.10.1"],
            },
            {
                "type": "OTHER",
                "gateway": ["10.10.10.1"],
                "subnetmask": [],
                "ip": [],
                "dns": [],
                "mac": [],
                "network": [],
                "search_domain": None,
                "first_connected": None,
                "vlan": None,
                "name": None,
                "metric": None,
                "dhcp": False,
                "enabled": None,
            },
        ),
        (
            {
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 1,
                "DefaultGateway": ["10.10.10.2"],
                "NetworkAddress": None,
                "NetworkInterfaceInstallTimestamp": None,
                "DhcpIPAddress": None,
                "DhcpNameServer": None,
                "DhcpSubnetMask": None,
                "Domain": None,
                "VlanID": None,
                "InterfaceMetric": None,
                "Name": None,
                "EnableDHCP": None,
            },
            {
                "type": "OTHER",
                "gateway": ["10.10.10.2"],
                "subnetmask": [],
                "mac": [],
                "ip": [],
                "first_connected": None,
                "dns": [],
                "network": [],
                "search_domain": None,
                "vlan": None,
                "metric": None,
                "name": None,
                "dhcp": False,
                "enabled": None,
            },
        ),
    ],
)
def test_windows_network(
    mock_values: dict[str, MockRegVal],
    expected_values: dict[str, str | int],
    target_win: Target,
) -> None:
    mock_value_dict = {key: MockRegVal(name=key, value=value) for key, value in mock_values.items()}
    mock_registry = Mock()
    mock_registry.keys.return_value = [mock_registry]
    mock_registry.key.side_effect = lambda name: (
        mock_registry
        if name
        in [
            f"{REGISTRY_KEY_CONNECTION}TESTINGINSTANCEID\\Connection",
            f"{REGISTRY_KEY_INTERFACE}TESTINGINSTANCEID",
        ]
        else None
    )
    mock_registry.__len__ = lambda self: len(mock_value_dict)
    mock_registry.subkeys.return_value = [mock_registry]
    mock_registry.value.side_effect = lambda field: mock_value_dict.get(field, MockRegVal(name=field, value=None))
    mock_registry.values.return_value = list(mock_value_dict.values())

    with (
        patch("dissect.target.plugins.os.windows.generic.GenericPlugin", return_value=""),
        patch("dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", return_value="hostname"),
        patch.object(target_win, "registry", mock_registry),
    ):
        network = target_win.network
        assert network.ips() == expected_values["ip"]
        assert network.dns() == expected_values["dns"]
        assert network.gateways() == expected_values["gateway"]
        assert network.macs() == expected_values["mac"]

        network_interface = list(network.interfaces())[0]
        assert network_interface.network == expected_values["network"]
        assert network_interface.first_connected == expected_values["first_connected"]
        assert network_interface.type == expected_values["type"]
        assert network_interface.vlan == expected_values["vlan"]
        assert network_interface.name == expected_values["name"]
        assert network_interface.search_domain == expected_values["search_domain"]
        assert network_interface.metric == expected_values["metric"]
        assert network_interface.subnetmask == expected_values["subnetmask"]
        assert network_interface.dhcp == expected_values["dhcp"]
        assert network_interface.enabled == expected_values["enabled"]


@pytest.mark.parametrize(
    "mock_values",
    [
        {
            "NetCfgInstanceId": "TESTINGINSTANCEID",
            "*IfType": None,
        },
    ],
)
def test_windows_network_none(
    mock_values: dict[str, MockRegVal],
    target_win: Target,
) -> None:
    mock_value_dict = {key: MockRegVal(name=key, value=value) for key, value in mock_values.items()}
    mock_registry = Mock()
    mock_registry.keys.return_value = [mock_registry]
    mock_registry.key.side_effect = lambda name: (
        mock_registry
        if name
        in [
            f"{REGISTRY_KEY_CONNECTION}TESTINGINSTANCEID\\Connection",
            f"{REGISTRY_KEY_INTERFACE}TESTINGINSTANCEID",
        ]
        else None
    )
    mock_registry.__len__ = lambda self: len(mock_value_dict)
    mock_registry.subkeys.return_value = [mock_registry]
    mock_registry.value.side_effect = lambda field: mock_value_dict.get(field, MockRegVal(name=field, value=None))
    mock_registry.values.return_value = list(mock_value_dict.values())

    with (
        patch("dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", return_value="hostname"),
        patch.object(target_win, "registry", mock_registry),
    ):
        network = target_win.network
        network_interface = list(network.interfaces())
        assert network.ips() == []
        assert network.dns() == []
        assert network.gateways() == []
        assert network.macs() == []
        assert network_interface == []


@pytest.mark.parametrize(
    "mock_values, expected_values",
    [
        (
            {
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 24,
                "NetworkAddress": "FE:EE:EE:EE:EE:ED",
                "NetworkInterfaceInstallTimestamp": 130005216000000000,
                "DhcpDefaultGateway": ["192.168.0.1"],
                "DefaultGateway": ["10.0.0.1"],
                "DhcpIPAddress": "192.168.0.10",
                "IPAddress": "10.0.0.10",
                "DhcpNameServer": "192.168.0.2",
                "NameServer": "10.0.0.2",
                "SubnetMask": "255.255.255.0",
                "DhcpSubnetMask": "255.255.255.0",
                "VlanID": 10,
                "InterfaceMetric": 20,
                "Domain": "corp",
                "DhcpDomain": "corp",
                "EnableDHCP": 1,
            },
            [
                {
                    "ip": ["192.168.0.10"],
                    "dns": ["192.168.0.2"],
                    "gateway": ["192.168.0.1"],
                    "mac": "FE:EE:EE:EE:EE:ED",
                    "subnetmask": ["255.255.255.0"],
                    "network": ["192.168.0.0/24"],
                    "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                    "type": "SOFTWARE_LOOPBACK",
                    "vlan": 10,
                    "name": None,
                    "search_domain": ["corp"],
                    "metric": 20,
                    "dhcp": True,
                    "enabled": True,
                },
                {
                    "ip": ["10.0.0.10"],
                    "dns": ["10.0.0.2"],
                    "gateway": ["10.0.0.1"],
                    "mac": "FE:EE:EE:EE:EE:ED",
                    "subnetmask": ["255.255.255.0"],
                    "network": ["10.0.0.0/24"],
                    "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                    "type": "SOFTWARE_LOOPBACK",
                    "vlan": 10,
                    "name": None,
                    "search_domain": ["corp"],
                    "metric": 20,
                    "dhcp": False,
                    "enabled": None,
                },
            ],
        ),
    ],
)
def test_network_dhcp_and_static(
    mock_values: dict[str, str | int | list[str] | None],
    expected_values: list[dict[str, str | int | list[str] | None]],
    target_win: Target,
):
    mock_value_dict = {key: MockRegVal(name=key, value=value) for key, value in mock_values.items()}
    mock_registry = Mock()
    mock_registry.keys.return_value = [mock_registry]
    mock_registry.key.side_effect = lambda name: (
        mock_registry
        if name
        in [
            f"{REGISTRY_KEY_CONNECTION}TESTINGINSTANCEID\\Connection",
            f"{REGISTRY_KEY_INTERFACE}TESTINGINSTANCEID",
        ]
        else None
    )
    mock_registry.__len__ = lambda self: len(mock_value_dict)
    mock_registry.subkeys.return_value = [mock_registry]
    mock_registry.value.side_effect = lambda field: mock_value_dict.get(field, MockRegVal(name=field, value=None))
    mock_registry.values.return_value = list(mock_value_dict.values())

    with (
        patch("dissect.target.plugins.os.windows.generic.GenericPlugin", return_value=""),
        patch("dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", return_value="hostname"),
        patch.object(target_win, "registry", mock_registry),
    ):
        ips = []
        dns = []
        gateways = []
        macs = []

        network = target_win.network
        interfaces = list(network.interfaces())

        for interface, expected in zip(interfaces, expected_values):
            assert interface.ip == expected["ip"]
            ips.extend(interface.ip)
            assert interface.dns == expected["dns"]
            dns.extend(interface.dns)
            assert interface.gateway == expected["gateway"]
            gateways.extend(interface.gateway)
            assert interface.mac == expected["mac"]
            macs.append(interface.mac)
            assert interface.network == expected["network"]
            assert interface.first_connected == expected["first_connected"]
            assert interface.type == expected["type"]
            assert interface.vlan == expected["vlan"]
            assert interface.name == expected["name"]
            assert interface.search_domain == expected["search_domain"]
            assert interface.metric == expected["metric"]
            assert interface.subnetmask == expected["subnetmask"]
            assert interface.dhcp == expected["dhcp"]
            assert interface.enabled == expected["enabled"]

        assert network.ips() == ips
        assert network.dns() == dns
        assert network.gateways() == gateways
        assert network.macs() == macs
