from typing import Iterator
from unittest import mock

import pytest

from dissect.target.plugins.os.unix.bsd.osx.network import MacNetworkPlugin
from dissect.target.target import Target


@pytest.fixture
def almost_empty_plist() -> Iterator[dict]:
    yield {"CurrentSet": {}}


@pytest.fixture
def fake_plist() -> Iterator[dict]:
    yield {
        "CurrentSet": "/Sets/1",
        "NetworkServices": {
            "1": {
                "DNS": {"ServerAddresses": ["8.8.8.8"]},
                "IPv4": {
                    "Addresses": ["192.122.13.34"],
                    "Router": "8.8.8.8",
                },
                "Interface": {
                    "DeviceName": "en0",
                    "Type": "Ethernet",
                },
            },
        },
        "Sets": {
            "1": {
                "Network": {
                    "Global": {"IPv4": {"ServiceOrder": ["1"]}},
                },
            },
        },
        "VirtualNetworkInterfaces": {"VLAN": {"vlan0": {"Tag": 2}}},
    }


@pytest.fixture
def vlan0(fake_plist: dict) -> Iterator[dict]:
    fake_plist["NetworkServices"]["1"]["Interface"].update({"DeviceName": "vlan0"})
    yield fake_plist


@pytest.fixture
def inactive(fake_plist: dict) -> Iterator[dict]:
    fake_plist["NetworkServices"]["1"].update({"__INACTIVE__": True})
    yield fake_plist


@pytest.fixture
def ipv6(fake_plist: dict) -> Iterator[dict]:
    del fake_plist["NetworkServices"]["1"]["IPv4"]
    fake_plist["NetworkServices"]["1"]["IPv6"] = {"Addresses": ["::1"]}
    yield fake_plist


@pytest.fixture
def reorder(fake_plist: dict) -> Iterator[dict]:
    fake_plist["Sets"]["1"]["Network"]["Global"]["IPv4"]["ServiceOrder"] = ["2", "1"]
    yield fake_plist


@pytest.fixture
def double(fake_plist: dict) -> Iterator[dict]:
    fake_plist["NetworkServices"]["2"] = fake_plist["NetworkServices"]["1"]
    yield fake_plist


@pytest.fixture
def dhcp(fake_plist: dict) -> Iterator[dict]:
    fake_plist["NetworkServices"]["1"]["IPv4"].update({"ConfigMethod": "DHCP"})
    yield fake_plist


@pytest.mark.parametrize(
    "lease,netinfo_param,expected,count",
    [
        ({"IPAddress": None}, "almost_empty_plist", [], 0),
        (
            {},
            "fake_plist",
            [
                (0, "hostname", ["dummys Mac"]),
                (0, "domain", ["None"]),
                (0, "name", ["en0"]),
                (0, "type", ["Ethernet"]),
                (0, "ip", ["192.122.13.34"]),
                (0, "gateway", ["8.8.8.8"]),
                (0, "dns", ["8.8.8.8"]),
                (0, "vlan", ["None"]),
                (0, "enabled", ["True"]),
                (0, "interface_service_order", ["0"]),
                (0, "mac", []),
                (0, "vlan", ["None"]),
            ],
            1,
        ),
        (
            {"IPAddress": "10.0.0.2"},
            "dhcp",
            [
                (0, "ip", sorted(["10.0.0.2"])),
            ],
            1,
        ),
        (
            {},
            "vlan0",
            [
                (0, "vlan", ["2"]),
            ],
            1,
        ),
        (
            {},
            "inactive",
            [
                (0, "enabled", ["False"]),
            ],
            1,
        ),
        (
            {},
            "ipv6",
            [
                (0, "ip", ["::1"]),
            ],
            1,
        ),
        (
            {},
            "reorder",
            [
                (0, "interface_service_order", ["1"]),
            ],
            1,
        ),
        (
            {},
            "double",
            [
                (0, "enabled", ["True"]),
                (1, "enabled", ["True"]),
            ],
            2,
        ),
    ],
)
def test_macos_network(
    target_osx: Target, lease: dict, netinfo_param: str, expected: dict, count: int, request: pytest.FixtureRequest
) -> None:
    plistnetwork = request.getfixturevalue(netinfo_param)
    with mock.patch(
        "dissect.target.plugins.os.unix.bsd.osx.network.MacNetworkPlugin._plistlease", return_value=lease
    ), mock.patch(
        "dissect.target.plugins.os.unix.bsd.osx.network.MacNetworkPlugin._plistnetwork", return_value=plistnetwork
    ):
        network = MacNetworkPlugin(target_osx)

    interfaces = list(network.interfaces())
    assert len(interfaces) == count
    for index, key, value in expected:
        attr = getattr(interfaces[index], key)
        if not isinstance(attr, list):
            attr = [attr]
        attr = list(sorted(map(str, attr)))
        assert attr == value
