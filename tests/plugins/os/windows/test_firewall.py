from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.firewall import WindowsFirewallPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_firewall_rules(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """Test if we parse Windows Registry Firewall Rules correctly."""

    rules_name = "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    rules_key = VirtualKey(hive_hklm, rules_name)

    rules_key.add_value(
        "{some-uuid}",
        "v13.37|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=1234|App=C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe|Name=Microsoft Edge Example|Desc=Inbound example rule for Microsoft Edge|EmbedCtxt=Microsoft Edge|",  # noqa: E501
    )

    # See if we can parse dll table references
    rules_key.add_value(
        "Some-GPO-Rule-Name",
        "v13.37|Action=Allow|Active=FALSE|Dir=In|Protocol=148|Profile=Domain|LPort=5678|RA4=ExampleKeyword|RA6=AnotherExampleKeyword|App=%SystemRoot%\\system32\\svchost.exe|Svc=ExampleSvc|Name=@Example.dll,-12345|Desc=@Example.dll,-6789|EmbedCtxt=@Example.dll,-01234|",
    )

    # Malformed default Windows 11 rule
    rules_key.add_value(
        "DisplayEnhancementService Deny All Outbound",
        "V2.0|Action=Block|Dir=out|App=%SystemRoot%\\System32\\svchost.exe|Svc==DisplayEnhancementService|Name=Block outbound traffic from BFE|",  # noqa: E501
    )

    # Apparently we can use letters instead of numbers now too for protocol
    rules_key.add_value(
        "SearchProtocolHost-2",
        "V2.0|Action=Allow|Dir=Out|Protocol=tcp|rport=3268,389,563,993,995,80,443|App=%SystemRoot%\\system32\\SearchProtocolHost.exe|Name=Allow outbound traffic from SearchProtocolHost on specific ports|",  # noqa: E501
    )

    # Test port ranges
    rules_key.add_value(
        "WMPNetworkSvc-2",
        "V2.0|Action=Block|Dir=In|LPort=1-553,555-8553,8555-65535|Protocol=6|App=%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe|Svc=WMPNetworkSvc|Name=Windows Media Player Network Sharing Service service hardening - Block any other incoming TCP traffic|",  # noqa: E501
    )

    hive_hklm.map_key(rules_name, rules_key)

    target_win_users.add_plugin(WindowsFirewallPlugin)
    records = list(target_win_users.firewall.rules())

    assert len(records) == 5

    assert records[0].key == "{some-uuid}"
    assert records[0].version == "v13.37"
    assert records[0].action == "ALLOW"
    assert records[0].active
    assert records[0].dir == "OUT"
    assert records[0].protocol == "UDP"
    assert records[0].lport == ["1234"]
    assert records[0].app == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    assert records[0].name == "Microsoft Edge Example"
    assert records[0].desc == "Inbound example rule for Microsoft Edge"
    assert records[0].embedctxt == "Microsoft Edge"
    assert (
        records[0].source
        == "HKLM\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    )

    assert records[1].key == "Some-GPO-Rule-Name"
    assert records[1].version == "v13.37"
    assert records[1].action == "ALLOW"
    assert not records[1].active
    assert records[1].dir == "IN"
    assert records[1].protocol == "UNASSIGNED_148"  # test IntEnum._missing_
    assert records[1].profile == "Domain"
    assert records[1].lport == ["5678"]
    assert records[1].ra4 == "ExampleKeyword"
    assert records[1].ra6 == "AnotherExampleKeyword"
    assert records[1].app == "c:\\Windows\\system32\\svchost.exe"
    assert records[1].svc == "ExampleSvc"
    assert records[1].name == "@Example.dll,-12345"
    assert records[1].desc == "@Example.dll,-6789"
    assert records[1].embedctxt == "@Example.dll,-01234"
    assert (
        records[1].source
        == "HKLM\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    )

    assert records[2].key == "DisplayEnhancementService Deny All Outbound"
    assert records[2].version == "V2.0"
    assert records[2].action == "BLOCK"
    assert records[2].dir == "OUT"
    assert records[2].app == "c:\\Windows\\System32\\svchost.exe"
    assert records[2].svc == "=DisplayEnhancementService"
    assert records[2].name == "Block outbound traffic from BFE"
    assert (
        records[2].source
        == "HKLM\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    )

    assert records[3].key == "SearchProtocolHost-2"
    assert records[3].version == "V2.0"
    assert records[3].action == "ALLOW"
    assert records[3].dir == "OUT"
    assert records[3].protocol == "TCP"
    assert records[3].rport == ["3268", "389", "563", "993", "995", "80", "443"]
    assert records[3].app == "c:\\Windows\\system32\\SearchProtocolHost.exe"
    assert records[3].name == "Allow outbound traffic from SearchProtocolHost on specific ports"
    assert (
        records[3].source
        == "HKLM\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    )

    assert records[4].key == "WMPNetworkSvc-2"
    assert records[4].version == "V2.0"
    assert records[4].action == "BLOCK"
    assert records[4].dir == "IN"
    assert records[4].lport == ["1-553", "555-8553", "8555-65535"]
    assert records[4].protocol == "TCP"
    assert records[4].app == "%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe"
    assert records[4].svc == "WMPNetworkSvc"
    assert (
        records[4].name
        == "Windows Media Player Network Sharing Service service hardening - Block any other incoming TCP traffic"
    )
    assert (
        records[4].source
        == "HKLM\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    )


def test_windows_firewall_logs(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we parse Windows Firewall ``pfirewall.log`` files correctly."""

    buf = """\
    #Version: 1.5
    #Software: Microsoft Windows Firewall
    #Time Format: Local
    #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

    2022-01-01 13:37:00 ALLOW TCP 1.2.3.4 5.6.7.8 1234 5678 1337 - - - - - - - SEND
    2022-01-01 13:37:01 DROP UDP 1.2.3.4 5.6.7.8 12345 6789 0 - - - - - - - RECEIVE
    2022-01-01 13:37:02 DROP UDP 1.2.3.4 5.6.7.8 12345 6789 0 - - - - - - - RECEIVE
    """  # noqa: E501

    fs_win.map_file_fh("Windows/System32/LogFiles/Firewall/pfirewall.log", BytesIO(textwrap.dedent(buf).encode()))

    target_win.add_plugin(WindowsFirewallPlugin)

    records = list(target_win.firewall.logs())

    assert len(records) == 3

    assert records[0].ts == datetime(2022, 1, 1, 13, 37, 0, tzinfo=timezone.utc)
    assert records[0].action == "ALLOW"
    assert records[0].protocol == "TCP"
    assert records[0].src_ip == "1.2.3.4"
    assert records[0].dst_ip == "5.6.7.8"
    assert records[0].src_port == 1234
    assert records[0].dst_port == 5678
    assert records[0].size == 1337
    assert not records[0].tcpflags
    assert not records[0].tcpsyn
    assert not records[0].tcpack
    assert not records[0].tcpwin
    assert not records[0].icmptype
    assert not records[0].icmpcode
    assert not records[0].info
    assert records[0].path == "SEND"

    assert records[1].ts == datetime(2022, 1, 1, 13, 37, 1, tzinfo=timezone.utc)
    assert records[1].action == "DROP"
    assert records[1].protocol == "UDP"
    assert records[1].src_ip == "1.2.3.4"
    assert records[1].dst_ip == "5.6.7.8"
    assert records[1].src_port == 12345
    assert records[1].dst_port == 6789
    assert records[1].size == 0
    assert not records[1].tcpflags
    assert not records[1].tcpsyn
    assert not records[1].tcpack
    assert not records[1].tcpwin
    assert not records[1].icmptype
    assert not records[1].icmpcode
    assert not records[1].info
    assert records[1].path == "RECEIVE"
