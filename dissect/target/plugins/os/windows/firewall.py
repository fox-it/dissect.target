from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from typing import TYPE_CHECKING, Any, Callable, Final

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.network import IANAProtocol
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target


WindowsFirewallLogRecord = TargetRecordDescriptor(
    "windows/firewall/log",
    [
        ("datetime", "ts"),
        ("string", "action"),
        ("string", "protocol"),
        ("net.ipaddress", "src_ip"),
        ("net.ipaddress", "dst_ip"),
        ("varint", "src_port"),
        ("varint", "dst_port"),
        ("filesize", "size"),
        ("string", "tcpflags"),
        ("string", "tcpsyn"),
        ("string", "tcpack"),
        ("string", "tcpwin"),
        ("string", "icmptype"),
        ("string", "icmpcode"),
        ("string", "info"),
        ("string", "path"),
        ("path", "source"),
    ],
)


class WindowsFirewallPlugin(Plugin):
    """Windows Firewall plugin."""

    __namespace__ = "firewall"

    RULE_KEYS = (
        # Defaults
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Defaults\\FirewallPolicy\\FirewallRules",
        # Parameters
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\Mdm\\FirewallRules",
        # Legacy
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules",
        # Other
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\Configurable\\System",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\Static\\System",
    )

    LOGGING_KEYS = (
        # Defaults
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Defaults\\FirewallPolicy\\PublicProfile\\Logging"
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Defaults\\FirewallPolicy\\StandardProfile\\Logging"
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Defaults\\FirewallPolicy\\DomainProfile\\Logging"
        # Parameters
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\\Logging",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\Logging",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\Logging",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.keys = list(self.find_rule_keys())
        self.log_paths = list(self.find_log_paths())

    def find_rule_keys(self) -> Iterator[RegistryKey]:
        for key in self.RULE_KEYS:
            yield from self.target.registry.keys(key)

    def find_log_paths(self) -> Iterator[Path]:
        seen = set()

        for path in self.target.fs.path("sysvol/Windows/System32/LogFiles/Firewall").glob("pfirewall*"):
            seen.add(path)
            yield path

        if self.target.has_function("registry"):
            for log_key in self.LOGGING_KEYS:
                for key in self.target.registry.keys(log_key):
                    try:
                        log_path = self.target.resolve(key.value("LogFilePath").value)
                        if log_path.is_file() and log_path not in seen:
                            seen.add(log_path)
                            yield log_path
                    except (ValueError, RegistryValueNotFoundError):  # noqa: PERF203
                        pass

    def check_compatible(self) -> None:
        if not self.keys and not self.log_paths:
            raise UnsupportedPluginError("No Windows Firewall registry keys or log files found on target")

    @export(record=DynamicDescriptor(["string", "boolean"]))
    def rules(self) -> Iterator[DynamicDescriptor]:
        """Return firewall rules saved in the Windows registry.

        For a Windows operating system, the Firewall rules are stored in the
        ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules`` registry key.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16

        Yields dynamic records with usually the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            key (string): The rule key name.
            version (string): The version field of the rule.
            action (string): The action of the rule.
            active (boolean): Whether the rule is active.
            dir (string): The direction of the rule.
            protocol (string): The specified IANA protocol (UDP, TCP, etc).
            lport (string): The listening port or range of the rule.
            rport (string): The receiving port or range the rule.
            profile (string): The Profile field of the rule.
            app (string): The App field of the rule.
            svc (string): The Svc of the rule.
            name (string): The Name of the rule.
            desc (string): The Desc of the rule.
            embed_ctxt (string): The EmbedCtxt of the rule.
        """  # noqa: E501

        FIELD_MAP: Final[dict[str, str]] = {
            "app": "path",
            "active": "boolean",
            # protocol int is translated to a string at runtime
            # lport and rport can be a string (e.g. port ranges or other text)
            "lport": "string[]",
            "rport": "string[]",
        }
        VALUE_MAP: Final[dict[str, Callable[[str], Any]]] = {"active": lambda val: val.upper() == "TRUE"}

        for reg in self.keys:
            for entry in reg.values():
                r = [
                    ("string", "key"),
                    ("string", "version"),
                ]
                data = {}

                pairs: list[str] = entry.value.split("|")
                data["version"] = pairs.pop(0)

                for kv in pairs:
                    key, _, value = kv.partition("=")

                    if not (key := key.lower()):
                        continue

                    field_type = FIELD_MAP.get(key, "string")
                    r.append((field_type, key))

                    try:
                        value = VALUE_MAP[key](value)
                    except KeyError:
                        pass
                    data[key] = value

                # Resolve file paths to TargetPaths
                if "app" in data:
                    data["app"] = self.target.resolve(data["app"])

                # Translate protocol numbers to IANA names
                if protocol := data.get("protocol"):
                    if protocol.isnumeric():
                        data["protocol"] = IANAProtocol(int(protocol)).name
                    elif protocol.isalpha():
                        data["protocol"] = protocol.upper()

                # Make sure actions and directions are consistent
                if "action" in data:
                    data["action"] = data["action"].upper()
                if "dir" in data:
                    data["dir"] = data["dir"].upper()

                # Put port ranges in a list
                if "lport" in data:
                    data["lport"] = data["lport"].split(",")
                if "rport" in data:
                    data["rport"] = data["rport"].split(",")

                r.append(("path", "source"))

                yield TargetRecordDescriptor("windows/firewall/rule", r)(
                    key=entry.name,
                    **data,
                    source=f"HKLM\\{reg.path}",
                    _target=self.target,
                )

    @export(record=WindowsFirewallLogRecord)
    def logs(self) -> Iterator[WindowsFirewallLogRecord]:
        """Parse Windows Firewall log files.

        Currently parses ``pfirewall*`` files in ``sysvol\\Windows\\System32\\LogFiles\\Firewall\\`` only.
        Does not yet parse dynamically set log locations e.g. ``netsh advfirewall set currentprofile logging filename``.

        References:
            - https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging

        Yields Windows Firewall log records with the following fields:

        .. code-block:: text

            ts (datetime): The timestamp of the log entry.
            hostname (string): The target hostname.
            domain (string): The target domain.
            action (string): Allow or Block.
            protocol (string): TCP, UDP or other IANA protocol value.
            src_ip (net.ipaddress): Source IP address.
            dst_ip (net.ipaddress): Destination IP address.
            src_port (varint): Source port number.
            dst_port (varint): Destination port number.
            size (filesize): Size in bytes of the packet(s).
            tcpflags (string): TCP header control flags.
            tcpsyn (string): TCP sequence number.
            tcpack (string): TCP acknowledgement number.
            tcpwin (string): TCP window size in bytes.
            icmptype (string): ICMP packet type.
            icmpcode (string): ICMP packet code.
            info (string): Additional information.
            path (string): Direction of the traffic, either SEND, RECEIVE, FORWARD or UNKNOWN.
            source (path): Source path of the record log line.
        """

        for path in self.log_paths:
            with path.open("rt") as fh:
                try:
                    header = list(islice(fh, 4))
                    config = LogConfig(header)
                except Exception as e:
                    self.target.log.warning("Unable to read Windows Firewall log file config in %s: %s", path, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                if config.version != 1.5:
                    self.target.log.warning(
                        "Unsupported Windows Firewall log file version %r in log file %s", header[0], path
                    )
                    continue

                for line in fh:
                    if not (line := line.strip()):
                        continue

                    entry = {
                        k.replace("-", "_"): v if v != "-" else None for k, v in zip(config.fields, line.split(" "))
                    }

                    entry["ts"] = datetime.strptime(f"{entry['date']} {entry['time']}", "%Y-%m-%d %H:%M:%S").replace(
                        tzinfo=self.target.datetime.tzinfo if config.time_format == "local" else timezone.utc
                    )
                    entry.pop("date")
                    entry.pop("time")

                    yield WindowsFirewallLogRecord(
                        **entry,
                        source=path,
                        _target=self.target,
                    )


@dataclass
class LogConfig:
    """Windows Firewall Log ``pfirewall.log`` file config parser.

    Fields can differ depending on configuration and version.

    Example structure of a regular ``pfirewall.log`` file:

    .. code-block::

        #Version: 1.5
        #Software: Microsoft Windows Firewall
        #Time Format: Local
        #Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

        2022-01-01 13:37:00 DROP UDP 1.2.3.4 5.6.7.8 1234 5678 1337 - - - - - - - RECEIVE
    """  # noqa: E501

    raw: list[str] = field(repr=False)
    version: float | None = None
    software: str | None = None
    time_format: str | None = None
    fields: list[str] | None = None

    def __post_init__(self):
        assert len(self.raw) == 4
        _, _, self.version = self.raw[0].strip().partition("#Version: ")
        _, _, self.software = self.raw[1].strip().partition("#Software: ")
        _, _, self.time_format = self.raw[2].strip().lower().partition("#time format: ")
        _, _, fields = self.raw[3].strip().partition("#Fields: ")
        self.version = float(self.version)
        self.fields = fields.split(" ")
