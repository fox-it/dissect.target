from __future__ import annotations

import pytest

from dissect.target.helpers.regex.ipaddress import extract_ips


@pytest.mark.parametrize(
    "input_ip, expected_output",
    [
        # Correct ipv6 addresses
        ("1::", "1::"),
        ("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7::"),
        ("1::8", "1::8"),
        ("1:2:3:4:5:6::8", "1:2:3:4:5:6::8"),
        ("1::7:8", "1::7:8"),
        ("1:2:3:4:5::7:8", "1:2:3:4:5::7:8"),
        ("1:2:3:4:5::8", "1:2:3:4:5::8"),
        ("1::6:7:8", "1::6:7:8"),
        ("1:2:3:4::6:7:8", "1:2:3:4::6:7:8"),
        ("1:2:3:4::8", "1:2:3:4::8"),
        ("1::5:6:7:8", "1::5:6:7:8"),
        ("1:2:3::5:6:7:8", "1:2:3::5:6:7:8"),
        ("1:2:3::8", "1:2:3::8"),
        ("1::4:5:6:7:8", "1::4:5:6:7:8"),
        ("1:2::4:5:6:7:8", "1:2::4:5:6:7:8"),
        ("1:2::8", "1:2::8"),
        ("1::3:4:5:6:7:8", "1::3:4:5:6:7:8"),
        ("::2:3:4:5:6:7:8", "::2:3:4:5:6:7:8"),
        ("::8", "::8"),
        ("::", "::"),
        ("fe80::7:8%eth0", "fe80::7:8%eth0"),
        ("fe80::7:8%1", "fe80::7:8%1"),
        ("::255.255.255.255", "::255.255.255.255"),
        ("::ffff:255.255.255.255", "::ffff:255.255.255.255"),
        ("::FFFF:255.255.255.255", "::FFFF:255.255.255.255"),
        ("::ffff:0:255.255.255.255", "::ffff:0:255.255.255.255"),
        ("2001:db8:3:4::192.0.2.33", "2001:db8:3:4::192.0.2.33"),
        ("64:ff9b::192.0.2.33", "64:ff9b::192.0.2.33"),
        ("0:0:0:0:0:0:10.0.0.1", "0:0:0:0:0:0:10.0.0.1"),
        ("2001:db8:3:4::192.256.2.33", "2001:db8:3:4::192"),
        # Correct ipv4 addresses
        ("1.2.3.4", "1.2.3.4"),
        ("192.168.0.0/24", "192.168.0.0/24"),
        ("10.0.0.0/32", "10.0.0.0/32"),
        # Private IP address ranges
        ("0.0.0.0/8", "0.0.0.0/8"),
        ("10.0.0.0/16", "10.0.0.0/16"),
        ("127.0.0.0/8", "127.0.0.0/8"),
        ("169.254.0.0/16", "169.254.0.0/16"),
        ("172.16.0.0/12", "172.16.0.0/12"),
        ("192.0.0.170/31", "192.0.0.170/31"),
        ("192.0.2.0/24", "192.0.2.0/24"),
        ("192.168.0.0/16", "192.168.0.0/16"),
        ("192.18.0.0/15", "192.18.0.0/15"),
        ("192.51.100.0/24", "192.51.100.0/24"),
        ("203.0.113.0/24", "203.0.113.0/24"),
        ("240.0.0.0/4", "240.0.0.0/4"),
        ("255.255.255.255/32", "255.255.255.255/32"),
        # Valid but unlikely addresses
        ("1.02.34.56", None),
        ("1.002.34.56", None),
        ("010.010.010.010", None),
        ("10.0.001.001", None),
        # Bad addresses
        ("256.256.255.255", None),
        ("10.65.0.456", "10.65.0.45"),
        ("910.12.34.569", "10.12.34.56"),
        ("999.1.1.1/30", "99.1.1.1/30"),
        ("10.13.999.0/32", None),
        ("1.2.03.4", None),
        ("1.2.00.4", None),
        # Dates
        ("2025.08.31", None),  # best notation
        ("31.08.25", None),  # sane notation
        ("08.31.25", None),  # freedom units
        # Time notation
        ("2025-08-31T13:37:12.345678", None),
        ("the time is 15:00 right now.", None),
        ("to be exact, it is 15:00:01 at the moment.", None),
    ],
)
def test_ip_regexes(input_ip: str, expected_output: str | None):
    if expected_output is None:
        assert extract_ips(input_ip) == []
    else:
        assert extract_ips(input_ip) == [expected_output]
