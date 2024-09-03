import copy

import pytest

from dissect.target.plugins.os.unix.bsd.osx.network import MacNetworkPlugin
from dissect.target.target import Target

fake_plist = {
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
            "Proxies": {
                "GopherProxy": "9.9.9.9",
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


def vlan0(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    fake_plist["NetworkServices"]["1"]["Interface"].update({"DeviceName": "vlan0"})
    return fake_plist


def inactive(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    fake_plist["NetworkServices"]["1"].update({"__INACTIVE__": True})
    return fake_plist


def ipv6(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    del fake_plist["NetworkServices"]["1"]["IPv4"]
    fake_plist["NetworkServices"]["1"]["IPv6"] = {"Addresses": ["::1"]}
    return fake_plist


def reorder(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    fake_plist["Sets"]["1"]["Network"]["Global"]["IPv4"]["ServiceOrder"] = ["2", "1"]
    return fake_plist


def double(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    fake_plist["NetworkServices"]["2"] = fake_plist["NetworkServices"]["1"]
    return fake_plist


def dhcp(fake_plist: dict) -> dict:
    fake_plist = copy.deepcopy(fake_plist)
    fake_plist["NetworkServices"]["1"]["IPv4"].update({"ConfigMethod": "DHCP"})
    return fake_plist


@pytest.mark.parametrize(
    "lease,netinfo,expected,count",
    [
        ({"IPAddress": None}, {"CurrentSet": {}}, [], 0),
        (
            {},
            fake_plist,
            [
                (0, "hostname", ["dummys Mac"]),
                (0, "domain", ["None"]),
                (0, "name", ["en0"]),
                (0, "type", ["Ethernet"]),
                (0, "ip", ["192.122.13.34"]),
                (0, "proxy", ["9.9.9.9"]),
                (0, "gateway", ["8.8.8.8"]),
                (0, "dns", ["8.8.8.8"]),
                (0, "vlan", ["None"]),
                (0, "enabled", ["True"]),
                (0, "interface_service_order", ["0"]),
                (0, "mac", ["None"]),
                (0, "vlan", ["None"]),
            ],
            1,
        ),
        (
            {"IPAddress": "10.0.0.2"},
            dhcp(fake_plist),
            [
                (0, "ip", sorted(["10.0.0.2", "192.122.13.34"])),
            ],
            1,
        ),
        (
            {},
            vlan0(fake_plist),
            [
                (0, "vlan", ["2"]),
            ],
            1,
        ),
        (
            {},
            inactive(fake_plist),
            [
                (0, "enabled", ["False"]),
            ],
            1,
        ),
        (
            {},
            ipv6(fake_plist),
            [
                (0, "ip", ["::1"]),
            ],
            1,
        ),
        (
            {},
            reorder(fake_plist),
            [
                (0, "interface_service_order", ["1"]),
            ],
            1,
        ),
        (
            {},
            double(fake_plist),
            [
                (0, "enabled", ["True"]),
                (1, "enabled", ["True"]),
            ],
            2,
        ),
    ],
)
def test_macos_network(target_osx: Target, lease: dict, netinfo: dict, expected: dict, count: int) -> None:
    network = MacNetworkPlugin(target_osx)
    network.plistlease = lease
    network.plistnetwork = netinfo
    interfaces = list(network.interfaces())
    assert len(interfaces) == count
    for index, key, value in expected:
        attr = getattr(interfaces[index], key)
        if not isinstance(attr, list):
            attr = [attr]
        attr = list(sorted(map(str, attr)))
        assert attr == value
