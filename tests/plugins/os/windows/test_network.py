from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.plugins.os.windows.network import WindowsNetworkPlugin
from tests.conftest import change_controlset

if TYPE_CHECKING:
    from dissect.target.target import Target


@dataclass
class MockRegVal:
    name: str
    value: str | int


REGISTRY_KEY_INTERFACE = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
REGISTRY_KEY_CONTROLSET = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
REGISTRY_KEY_CONNECTION = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"


@pytest.mark.parametrize(
    ("mock_values", "expected_values"),
    [
        pytest.param(
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
                "name": "ETHERNET 0",
                "type": "OTHER",
                "enabled": True,
                "cidr": ["10.10.10.10/24"],
                "ip": ["10.10.10.10"],
                "gateway": ["10.10.10.1"],
                "dns": ["10.10.10.2"],
                "mac": ["DE:AD:BE:EF:DE:AD"],
                "metric": 15,
                "search_domain": ["work"],
                "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                "dhcp": True,
                "vlan": 12,
            },
            id="DHCP enabled",
        ),
        pytest.param(
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
                "type": "ETHERNET_CSMACD",
                "cidr": ["10.10.10.10/24"],
                "ip": ["10.10.10.10"],
                "gateway": ["10.10.10.1"],
                "dns": ["10.10.10.2"],
                "mac": ["DE:AD:BE:EF:DE:AD"],
                "metric": 5,
                "search_domain": ["local"],
                "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                "dhcp": False,
                "vlan": 11,
            },
            id="DHCP disabled",
        ),
        pytest.param(
            {
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "*IfType": 1,
                "DefaultGateway": ["10.10.10.1"],
            },
            {
                "type": "OTHER",
                "gateway": ["10.10.10.1"],
                "dhcp": False,
            },
            id="OTHER",
        ),
        pytest.param(
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
                "search_domain": [],
                "dhcp": False,
            },
            id="OTHER empty",
        ),
        pytest.param(
            {
                "NetCfgInstanceId": "TESTINGINSTANCEID",
                "EnableDHCP": 1,
                "DhcpIPAddress": "0.0.0.0",
                "DhcpSubnetMask": "255.255.255.0",
            },
            {
                "_NO_INTERFACES": True,
                "enabled": True,
                "cidr": {},  # and not {'/255.255.255.0'}
            },
            id="invalid cidr",
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
        patch(
            "dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", property(MagicMock(return_value="hostname"))
        ),
        patch.object(target_win, "registry", mock_registry),
    ):
        network = target_win.network
        assert network.ips() == expected_values.get("ip", [])
        assert network.dns() == expected_values.get("dns", [])
        assert network.gateways() == expected_values.get("gateway", [])
        assert network.macs() == expected_values.get("mac", [])

        if expected_values.get("_NO_INTERFACES"):
            with pytest.raises(StopIteration):
                next(iter(network.interfaces()))
            return

        network_interface = next(iter(network.interfaces()))
        assert network_interface.name == expected_values.get("name")
        assert network_interface.type == expected_values.get("type")
        assert network_interface.enabled == expected_values.get("enabled")
        assert network_interface.cidr == expected_values.get("cidr", [])
        assert network_interface.metric == expected_values.get("metric")
        assert network_interface.search_domain == expected_values.get("search_domain", [])
        assert network_interface.first_connected == expected_values.get("first_connected")
        assert network_interface.dhcp == expected_values.get("dhcp")
        assert network_interface.vlan == expected_values.get("vlan")


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
        patch(
            "dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", property(MagicMock(return_value="hostname"))
        ),
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
    ("mock_values", "expected_values"),
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
                "NameServer": "10.0.0.2 10.0.0.3",
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
                    "name": None,
                    "type": "SOFTWARE_LOOPBACK",
                    "enabled": True,
                    "cidr": ["192.168.0.10/24"],
                    "ip": ["192.168.0.10"],
                    "gateway": ["192.168.0.1"],
                    "dns": ["192.168.0.2"],
                    "mac": ["FE:EE:EE:EE:EE:ED"],
                    "metric": 20,
                    "search_domain": ["corp"],
                    "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                    "dhcp": True,
                    "vlan": 10,
                },
                {
                    "name": None,
                    "type": "SOFTWARE_LOOPBACK",
                    "enabled": None,
                    "cidr": ["10.0.0.10/24"],
                    "ip": ["10.0.0.10"],
                    "gateway": ["10.0.0.1"],
                    "dns": ["10.0.0.2", "10.0.0.3"],
                    "mac": ["FE:EE:EE:EE:EE:ED"],
                    "metric": 20,
                    "search_domain": ["corp"],
                    "first_connected": datetime.fromisoformat("2012-12-21 00:00:00+00:00"),
                    "dhcp": False,
                    "vlan": 10,
                },
            ],
        ),
    ],
)
def test_network_dhcp_and_static(
    mock_values: dict[str, str | int | list[str] | None],
    expected_values: list[dict[str, str | int | list[str] | None]],
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
        patch(
            "dissect.target.plugins.os.windows._os.WindowsPlugin.hostname", property(MagicMock(return_value="hostname"))
        ),
        patch.object(target_win, "registry", mock_registry),
    ):
        network = target_win.network
        interfaces = list(network.interfaces())

        ips = set()
        dns = set()
        gateways = set()
        macs = set()

        for interface, expected in zip(interfaces, expected_values):
            ips.update({iface.ip for iface in interface.cidr})
            dns.update(interface.dns)
            gateways.update(interface.gateway)
            macs.update(interface.mac)

            assert sorted(str(x.ip) for x in interface.cidr) == expected["ip"]
            assert sorted(map(str, interface.dns)) == expected["dns"]
            assert interface.name == expected["name"]
            assert interface.type == expected["type"]
            assert interface.enabled == expected["enabled"]
            assert interface.cidr == expected["cidr"]
            assert interface.gateway == expected["gateway"]
            assert interface.mac == expected["mac"]
            assert interface.first_connected == expected["first_connected"]
            assert interface.metric == expected["metric"]
            assert interface.search_domain == expected["search_domain"]
            assert interface.dhcp == expected["dhcp"]
            assert interface.vlan == expected["vlan"]

        assert network.ips() == list(ips)
        assert network.dns() == list(dns)
        assert network.gateways() == list(gateways)
        assert network.macs() == list(macs)


@patch(
    "dissect.target.plugins.os.windows.registry.RegistryPlugin.controlsets",
    property(MagicMock(return_value=["ControlSet001", "ControlSet002", "ControlSet003"])),
)
def test_regression_duplicate_ips(target_win: Target, hive_hklm: VirtualHive) -> None:
    """Regression test for https://github.com/fox-it/dissect.target/issues/877."""

    change_controlset(hive_hklm, 3)

    # register the interfaces
    kvs = [
        (
            "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001",
            "{some-net-cfg-instance-uuid}",
        ),
        (
            "SYSTEM\\ControlSet002\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0002",
            "{some-net-cfg-instance-uuid}",
        ),
        (
            "SYSTEM\\ControlSet003\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0003",
            "{some-net-cfg-instance-uuid}",
        ),
    ]
    for name, value in kvs:
        key = VirtualKey(hive_hklm, name)
        key.add_value("NetCfgInstanceId", value)
        hive_hklm.map_key(name, key)

    # register interface dhcp ip addresses for three different control sets
    kvs = [
        ("SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{some-net-cfg-instance-uuid}", "1.2.3.4"),
        ("SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters\\Interfaces\\{some-net-cfg-instance-uuid}", "1.2.3.4"),
        ("SYSTEM\\ControlSet003\\Services\\Tcpip\\Parameters\\Interfaces\\{some-net-cfg-instance-uuid}", "5.6.7.8"),
    ]
    for name, value in kvs:
        key = VirtualKey(hive_hklm, name)
        key.add_value("DhcpIPAddress", value)
        hive_hklm.map_key(name, key)

    target_win.add_plugin(WindowsPlugin)
    target_win.add_plugin(WindowsNetworkPlugin)

    assert isinstance(target_win.ips, list)
    assert all(isinstance(ip, str) for ip in target_win.ips)
    assert len(target_win.ips) == 2
    assert sorted(target_win.ips) == ["1.2.3.4", "5.6.7.8"]
