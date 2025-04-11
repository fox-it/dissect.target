from __future__ import annotations

import re

IPV4_SEG = r"(?:25[0-5]|2[0-4]\d|[1]\d\d|[1-9]?\d)"
IPV4_ADDR = r"(?:" + IPV4_SEG + r"\.){3}" + IPV4_SEG + r"(?:\/(3[012]|[12]\d|[1-9]))?"

IPV6_SEG = r"(?:(?:[0-9a-fA-F]){1,4})"
IPV6_GROUPS = (
    # 1:2:3:4:5:6:7:8
    r"(?:" + IPV6_SEG + r":){7,7}" + IPV6_SEG,
    # 1:: - 1:2:3:4:5:6:7::
    r"(?:" + IPV6_SEG + r":){1,7}:",
    # 1::8 - 1:2:3:4:5:6::8 - 1:2:3:4:5:6::8
    r"(?:" + IPV6_SEG + r":){1,6}:" + IPV6_SEG,
    # 1::7:8 - 1:2:3:4:5::7:8 - 1:2:3:4:5::8
    r"(?:" + IPV6_SEG + r":){1,5}(?::" + IPV6_SEG + r"){1,2}",
    # 1::6:7:8 - 1:2:3:4::6:7:8 - 1:2:3:4::8
    r"(?:" + IPV6_SEG + r":){1,4}(?::" + IPV6_SEG + r"){1,3}",
    # 1::5:6:7:8 - 1:2:3::5:6:7:8 - 1:2:3::8
    r"(?:" + IPV6_SEG + r":){1,3}(?::" + IPV6_SEG + r"){1,4}",
    # 1::4:5:6:7:8 - 1:2::4:5:6:7:8 - 1:2::8
    r"(?:" + IPV6_SEG + r":){1,2}(?::" + IPV6_SEG + r"){1,5}",
    # 1::3:4:5:6:7:8 - 1::3:4:5:6:7:8 - 1::8
    IPV6_SEG + r":(?:(?::" + IPV6_SEG + r"){1,6})",
    # ::2:3:4:5:6:7:8 - ::2:3:4:5:6:7:8 - ::8 - ::
    r":(?:(?::" + IPV6_SEG + r"){1,7}|:)",
    # (link - local IPv6 addresses with zone index)
    # fe80::7:8%eth0 - fe80::7:8%1
    r"fe80:(?::" + IPV6_SEG + r"){0,4}%[0-9a-zA-Z]{1,}",
    # (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    # ::255.255.255.255 - ::ffff:255.255.255.255 - ::ffff:0:255.255.255.255
    r"::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]" + IPV4_ADDR,
    # (IPv4 - Embedded IPv6 Address)
    # 2001:db8:3:4::192.0.2.33 - 64:ff9b::192.0.2.33 - 0:0:0:0:0:0:10.0.0.1
    r"(?:" + IPV6_SEG + r":){1,6}:?[^\s:]" + IPV4_ADDR,
)
IPV6_ADDR = "|".join([f"(?:{group})" for group in IPV6_GROUPS[::-1]])  # Reverse rows for greedy match
IP_REGEX = re.compile(f"{IPV6_ADDR}|{IPV4_ADDR}", re.IGNORECASE)


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 and IPv6 addresses from an input string.

    Note: ``910.12.34.569`` matches ``10.12.34.56``, so always check your input!

    Deliberately does not find octal representations of IP addresses (e.g. ``010.010.010.010``)
    as this is generally discouraged and introduced ambiguity: the address could be interpreted as
    ``8.8.8.8`` or ``10.10.10.10``. Most indexing services such as Elasticsearch also do not accept
    octal representations of IP addresses.

    Resources:
        - https://github.com/GCHQ/CyberChef/blob/main/src/core/operations/ExtractIPAddresses.mjs
        - https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
    """

    return list({match.group() for match in IP_REGEX.finditer(text)})
