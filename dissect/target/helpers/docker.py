import re

from dissect.cstruct import cstruct

from dissect.target.helpers.protobuf import ProtobufVarint

# Resources:
# - https://github.com/moby/moby/pull/37092
# - https://github.com/cpuguy83/docker/blob/master/daemon/logger/local/doc.go
# - https://github.com/moby/moby/blob/master/api/types/plugins/logdriver/entry.proto
local_def = """
struct entry {
    uint32   header;

    // source
    uint8    s_type;        // 0x0a
    varint   s_len;         // 0x06
    char     source[s_len]; // stdout or stderr

    // timestamp
    uint8    t_type;        // 0x10
    varint   ts;            // timestamp in ums

    // message
    uint8    m_type;        // 0x1a
    varint   m_len;         // message length
    char     message[m_len];

    // partial_log_metadata not implemented

    uint32 footer;
};
"""

c_local = cstruct(endian=">")
c_local.addtype("varint", ProtobufVarint(cstruct=c_local, name="varint", size=1, signed=False, alignment=1))
c_local.load(local_def, compiled=False)

DOCKER_NS_REGEX = re.compile(r"\.(?P<nanoseconds>\d{7,})(?P<postfix>Z|\+\d{2}:\d{2})")


def convert_timestamp(timestamp: str) -> str:
    """
    Docker sometimes uses (unpadded) 9 digit nanosecond precision
    in their timestamp logs, eg. "2022-12-19T13:37:00.123456789Z".

    Python has no native %n nanosecond strptime directive, so we
    strip the last three digits from the timestamp to force
    compatbility with the 6 digit %f microsecond directive.
    """

    timestamp_nanoseconds_plus_postfix = timestamp[19:]
    match = DOCKER_NS_REGEX.match(timestamp_nanoseconds_plus_postfix)

    # Timestamp does not have nanoseconds if there is no match.
    if not match:
        return timestamp

    # Take the first six digits and reconstruct the timestamp.
    match = match.groupdict()
    microseconds = match["nanoseconds"][:6]
    return f"{timestamp[:19]}.{microseconds}{match['postfix']}"


def convert_ports(ports: dict) -> dict:
    """
    Depending on the state of the container (turned on or off) we
    can salvage forwarded ports for the container in different
    parts of the config.v2.json file.

    This function attempts to be agnostic and deals with
    "Ports" lists and "ExposedPorts" dicts.

    NOTE: This function makes a couple of assumptions and ignores
    ipv6 assignments. Feel free to improve this helper function.
    """

    fports = {}
    for key, value in ports.items():
        if isinstance(value, list):
            # NOTE: We ignore IPv6 assignments here.
            fports[key] = f"{value[0]['HostIp']}:{value[0]['HostPort']}"
        elif isinstance(value, dict):
            # NOTE: We make the assumption the default broadcast ip 0.0.0.0 was used.
            fports[key] = f"0.0.0.0:{key.split('/')[0]}"

    return fports


def hash_to_image_id(hash: str) -> str:
    """Convert the hash to an abbrevated docker image id."""
    return hash.split(":")[-1][:12]
