from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.esxi.log import HostdPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_esxi_6_log_hostd(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi6"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi6/hostd.1.gz")
    fs_esxi.map_file("/var/run/log/hostd.1.gz", data_file)

    target_esxi.add_plugin(HostdPlugin)

    results = list(target_esxi.hostd())
    assert len(results) == 2757
    # line without application
    assert results[0].ts == dt("2025-08-22T07:35:20.895Z")
    assert results[0].application is None
    assert (
        results[0].message == "time the service was last started, Section for VMware ESX, "
        "pid=2098599, version=6.7.0, build=14320388, option=Release"
    )

    # Multiline result
    assert results[1465].ts == dt("2025-08-22T07:35:25.968Z")
    assert results[1465].application == "hostd"
    assert results[1465].log_level == "info"
    assert results[1465].pid == 2098599
    assert results[1465].source == "/var/run/log/hostd.1.gz"
    assert (
        results[1465].message
        == "Loaded vSAN management connection configuration.\n port: 80\n path: /vsanperf\n sdkTunnelPath: /vsanperf\n "
        "retryDelaySec: 2\n maxPooledConnections: 2\n maxOpenConnections: 5\n privateKey: /etc/vmware/ssl/rui.key\n "
        "certificate: /etc/vmware/ssl/rui.crt"
    )

    assert results[1466].event_metadata == "Originator@6876 sub=SessionOrientedStub[0]"
    # Line with user/opID in metadata
    assert results[1747].ts == dt("2025-08-22T07:35:28.264Z")
    assert results[1747].user == "dcui"
    assert results[1747].op_id == "vsan-bdc1-4715"
    assert (
        results[1747].message
        == "Event 5 : User dcui@127.0.0.1 logged out (login time: Friday, 22 August, 2025 07:35:28 AM,"
        " number of API invocations: 0, user agent: VMware-client/6.5.0)"
    )


def test_esxi_7_log_hostd(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi 7"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi7/hostd.0.gz")
    fs_esxi.map_file("/scratch/log/hostd.0.gz", data_file)

    target_esxi.add_plugin(HostdPlugin)

    results = list(target_esxi.hostd())
    assert len(results) == 170
    # line without application
    assert results[0].ts == dt("2025-09-09T23:09:51.835Z")
    assert results[0].application is None
    assert (
        results[0].message == "last log rotation time, 2022-11-09T09:15:36.354Z - time the service was last started "
        "2022-11-09T09:15:36.339Z, Section for VMware ESX, pid=2099676, "
        "version=7.0.3, build=20328353, option=Release"
    )

    # Line with opId and user
    assert results[12].ts == dt("2025-09-09T23:10:06.616Z")
    assert results[12].log_level == "info"
    assert results[12].user == "vpxuser:VSPHERE.LOCAL\\vpxd-extension-b37a7345-e529-49c4-83a8-da77a48b1ce4"
    assert results[12].op_id == "sps-Main-112793-72-459406-de-2b-3426"
    assert (
        results[12].message
        == "Task Completed : haTask--vim.vslm.host.CatalogSyncManager.queryCatalogChange-118109847 Status success"
    )

    # multiline
    assert results[29].ts == dt("2025-09-09T23:10:51.079Z")
    assert results[29].application == "hostd"
    assert results[29].log_level == "info"
    assert results[29].pid == 2100292
    assert results[29].source == "/scratch/log/hostd.0.gz"
    assert (
        results[29].message
        == "VmkVprobSource::Post event: (vim.event.EventEx) {\n    key = 90,\n    chainId = -1,\n    createdTime = "
        '"1970-01-01T00:00:00Z",\n    userName = "",\n    host = (vim.event.HostEventArgument) {\n       name = '
        '"SRVESX12",\n       host = \'vim.HostSystem:ha-host\'\n    },\n    eventTypeId = "esx.audit.ssh.'
        'session.opened",\n    arguments = (vmodl.KeyAnyValue) [\n       (vmodl.KeyAnyValue) {\n          '
        'key = "1",\n          value = "root"\n       },\n       (vmodl.KeyAnyValue) {\n          key = "2",\n   '
        '       value = "192.168.101.96"\n       }\n    ],\n    objectId = "ha-host",\n    '
        'objectType = "vim.HostSystem",\n }'
    )


def test_esxi_8_log_hostd(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi 7"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi8/hostd.1.gz")
    fs_esxi.map_file("/var/log/hostd.1.gz", data_file)

    target_esxi.add_plugin(HostdPlugin)

    results = list(target_esxi.hostd())
    assert len(results) == 3192

    assert results[0].ts == dt("2025-10-28T08:36:40.940Z")
    assert results[0].application == "Hostd"
    assert (
        results[0].message == "- time the service was last started 2025-10-28T08:36:40.939Z, Section for VMware ESX, "
        "pid=132083, version=8.0.3, build=24677879, option=Release"
    )
    # test multiline line with metadata
    assert results[2749].ts == dt("2025-10-28T08:36:47.515Z")
    assert results[2749].user == ":vsanmgmtd"
    assert results[2749].message == (
        "Result:\n"
        " (vim.fault.NotAuthenticated) {\n"
        "    object = 'vim.host.StorageSystem:storageSystem', \n"
        '    privilegeId = "System.Read", \n'
        '    msg = "", \n'
        " }"
    )


def test_esxi_9_log_hostd(target_esxi: Target, fs_esxi: VirtualFilesystem) -> None:
    """Test with log from an ESXi 9"""
    data_file = absolute_path("_data/plugins/os/unix/esxi/log/esxi9/hostd.0.gz")
    fs_esxi.map_file("/var/log/hostd.0.gz", data_file)

    target_esxi.add_plugin(HostdPlugin)

    results = list(target_esxi.hostd())
    assert len(results) == 9554

    assert results[0].ts == dt("2025-10-28T16:01:55.286Z")
    assert results[0].log_level == "In(166)"
    assert results[0].user is None
    assert (
        results[0].message
        == "- time the service was last started 2025-10-28T16:01:55.285Z, Section for VMware ESXi, pid=132123, "
        "version=9.0.0, build=24678710, option=Release"
    )
    # multiline
    assert results[2377].ts == dt("2025-10-28T16:01:59.555Z")
    assert results[2377].application == "Hostd"
    assert results[2377].log_level == "Er(163)"
    assert results[2377].pid == 132123
    assert results[2377].source == "/var/log/hostd.0.gz"
    assert results[2377].message == (
        "Failed to load event type <EventType>\n"
        "                "
        "<eventTypeId>com.vmware.vim.vm.reboot.powerOff</eventTypeId>\n"
        "                <description>Virtual machine reboot converted to power off "
        "because the rebootPowerOff option is enabled</description>\n"
        "             </EventType>: No eventTypeID (spelling?)"
    )
    # bracket in metadata
    assert results[2821].ts == dt("2025-10-28T16:01:59.699Z")
    assert results[2821].event_metadata == "Originator@6876 sub=vmomi.soapStub[0]"
    assert results[2821].message == (
        "Resetting stub adapter: service state request failed; a: <<<cs p:0000006b69cebfe0, "
        "TCP:localhost.localdomain:80> >, /vsanperf>, pa: <<cs p:0000006b69cebfe0, TCP:localhost.localdomain:80> >, "
        "N7Vmacore4Http13HttpExceptionE(HTTP error response: Service Unavailable)\n"
        " [context]zKq7AVICAgAAADaReAEJaG9zdGQAACaiPWxpYnZtYWNvcmUuc28AAAtmNQB7Zy"
        "QAwmokAG4TJQBgOCUAu4hKAV5fCGxpYmMuc28uNgABMFwQ[/context]"
    )
