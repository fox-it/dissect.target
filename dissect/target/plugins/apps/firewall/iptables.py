import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal
from dissect.target.target import Target

PATTERN_IPTABLES_SAVE_GENERATED = re.compile(r"# Generated by (ip6?tables-save) v([.\d]+) on (.+)")

PATTERN_IPTABLES_SAVE_POLICY = re.compile(
    r":(?P<chain>[\w-]+) (?P<policy>[\w-]+|-) \[(?P<packet_count>\d+):(?P<byte_count>\d+)]"
)

PATTERN_IPTABLES_SAVE_RULE = re.compile(
    r"(?:\[(?P<packet_count>\d+):(?P<byte_count>\d+)] )?(?P<rule>-A (?P<chain>[\w-]+).+)"
)

IptablesSaveRecord = TargetRecordDescriptor(
    "application/firewall/iptables/save",
    [
        ("datetime", "ts"),
        ("string", "program"),
        ("string", "version"),
        ("string", "table"),
        ("string", "chain"),
        ("string", "type"),
        ("string", "rule"),
        ("varint", "packet_count"),
        ("varint", "byte_count"),
        ("path", "source"),
    ],
)


class IptablesSavePlugin(Plugin):
    """Parser for iptables-save (and ip6tables-save) rules.

    As iptables rules are not stored on disk by default, users
    that want persistent rules need to store them somewhere and
    reload them on boot. iptables provides tools to save and reload
    rules (iptables-save and iptables-restore). These tools
    do not have a default path to look for rules, however there
    are multiple commonly used paths.

    References:
        - https://git.netfilter.org/iptables/
    """

    COMMON_SAVE_PATHS = (
        # IPv4
        "/etc/iptables/rules.v4",
        "/etc/sysconfig/iptables",
        "/etc/iptables.rules",
        "/etc/iptablesRule.v4",
        "/etc/network/iptables.rules",
        # IPv6
        "/etc/iptables/rules.v6",
        "/etc/iptablesRule.v6",
        "/etc/sysconfig/ip6tables",
    )

    LOG_TIME_FORMAT = "%a %b  %d %H:%M:%S %Y"

    def __init__(self, target: Target):
        super().__init__(target)
        self._rule_files = list(self._get_rule_files())

    def check_compatible(self) -> bool:
        return len(self._rule_files) > 0

    @internal
    def _get_rule_files(self) -> Iterator[Path]:
        """Yield the paths of iptables-save output files."""
        for rule_path in self.COMMON_SAVE_PATHS:
            rule_path = self.target.fs.path(rule_path)

            if rule_path.exists():
                with rule_path.open("r") as h_rule:
                    first_line = h_rule.readline()

                if PATTERN_IPTABLES_SAVE_GENERATED.match(first_line):
                    yield rule_path

    @export(record=IptablesSaveRecord)
    def iptables(self) -> Iterator[IptablesSaveRecord]:
        """Return iptables rules saved using iptables-save."""

        tzinfo = self.target.datetime.tzinfo
        for rule_path in self._rule_files:
            current_program = None
            current_version = None
            current_ts = None
            current_table = None

            with rule_path.open("r") as h_rule:
                for line in h_rule:
                    line = line.strip()

                    if not line:
                        continue

                    elif match := PATTERN_IPTABLES_SAVE_GENERATED.match(line):
                        current_program, current_version, ts_string = match.groups()
                        current_ts = datetime.strptime(ts_string, self.LOG_TIME_FORMAT).replace(
                            tzinfo=tzinfo,
                        )

                    elif line.startswith("#") or line == "COMMIT":
                        continue

                    # Table
                    elif line.startswith("*"):
                        current_table = line.removeprefix("*")

                    # Policy
                    elif match := PATTERN_IPTABLES_SAVE_POLICY.match(line):
                        policy = match.groupdict()
                        yield IptablesSaveRecord(
                            ts=current_ts,
                            program=current_program,
                            version=current_version,
                            table=current_table,
                            chain=policy["chain"],
                            type="policy",
                            rule=policy["policy"],
                            packet_count=policy["packet_count"],
                            byte_count=policy["byte_count"],
                            source=rule_path,
                        )

                    # Rule
                    elif match := PATTERN_IPTABLES_SAVE_RULE.match(line):
                        rule = match.groupdict()
                        yield IptablesSaveRecord(
                            ts=current_ts,
                            program=current_program,
                            version=current_version,
                            table=current_table,
                            chain=rule["chain"],
                            type="rule",
                            rule=rule["rule"],
                            packet_count=rule["packet_count"] or None,
                            byte_count=rule["byte_count"] or None,
                            source=rule_path,
                        )
