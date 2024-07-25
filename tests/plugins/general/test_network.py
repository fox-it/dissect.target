from unittest.mock import patch

import pytest

from dissect.target.helpers.record import (
    MacInterfaceRecord,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugins.os.default.network import InterfaceRecord, NetworkPlugin
from dissect.target.target import Target


@pytest.fixture(params=[MacInterfaceRecord, WindowsInterfaceRecord, UnixInterfaceRecord])
def network_record(request: pytest.FixtureRequest) -> InterfaceRecord:
    return request.param(
        name="interface_name",
        type="physical",
        enabled=True,
        mac=["DE:AD:BE:EF:00:00"],
        ip=["10.42.42.10"],
        gateway=["10.42.42.1"],
        dns=["8.8.8.8", "1.1.1.1"],
        source="some_file",
    )


def test_base_network_plugin(target_bare: Target, network_record: InterfaceRecord) -> None:
    with patch.object(NetworkPlugin, "_interfaces", return_value=[network_record]):
        network = NetworkPlugin(target_bare)
        interfaces = list(network.interfaces())
        assert len(interfaces) == 1

        assert network.ips() == ["10.42.42.10"]
        assert network.gateways() == ["10.42.42.1"]
        assert network.macs() == ["DE:AD:BE:EF:00:00"]
        assert sorted(list(map(str, network.dns()))) == ["1.1.1.1", "8.8.8.8"]

        assert len(list(network.in_cidr("10.42.42.0/24"))) == 1
        assert len(list(network.in_cidr("10.43.42.0/24"))) == 0

        assert len(list(network.with_mac("DE:AD:BE:EF:00:00"))) == 1
        assert len(list(network.with_mac("DE:AD:BE:EF:00:01"))) == 0

        assert len(list(network.with_ip("10.42.42.10"))) == 1
        assert len(list(network.with_ip("10.42.42.42"))) == 0
