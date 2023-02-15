import re
from pathlib import Path
from typing import Iterator

from dissect.util.ts import from_unix

from dissect.target.helpers.fsutil import basename, open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

AuditRecord = TargetRecordDescriptor(
    "linux/log/audit",
    [
        ("datetime", "ts"),
        ("string", "audit_type"),
        ("varint", "audit_id"),
        ("string", "message"),
        ("path", "source"),
    ],
)

AUDIT_REGEX = re.compile(r"^type=(?P<audit_type>.*) msg=audit\((?P<ts>.*):(?P<audit_id>.*)\): (?P<message>.*)$")


class AuditPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    @internal
    def get_log_paths(self) -> list[Path]:
        default_config = "/etc/audit/auditd.conf"
        paths = ["/var/log/audit/audit.log"]

        if (path := self.target.fs.path(default_config)).exists():
            for line in path.open("rt"):
                line = line.strip()
                if not line or "log_file" not in line:
                    continue

                log_file = line.split("=")[-1].strip()
                if log_file not in paths:
                    paths.append(log_file)

        return paths

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @export(record=[AuditRecord])
    def audit(self) -> Iterator[AuditRecord]:
        """Return CentOS and RedHat audit information stored in /var/log/audit*.

        The audit log file on a Linux machine stores security-relevant information.
        Based on pre-configured rules. Log messages consist of space delimited key=value pairs.

        Sources:
            - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing
            - https://linux-audit.com/linux-audit-log-files-in-var-log-audit/
            - https://man7.org/linux/man-pages/man8/auditd.8.html
            - https://man7.org/linux/man-pages/man8/ausearch.8.html
            - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files
        """  # noqa: E501

        for path in self.log_paths:
            for file in self.target.fs.path(path).parent.glob(basename(path) + "*"):
                for line in open_decompress(file, "rt"):
                    match = AUDIT_REGEX.match(line)
                    if not match:
                        self.target.log.warning("Audit log file contains unrecognized format in %s", path)
                        continue

                    match = match.groupdict()
                    yield AuditRecord(
                        ts=from_unix(float(match["ts"])),
                        audit_type=match["audit_type"],
                        audit_id=int(match["audit_id"]),
                        message=match["message"].strip(),
                        source=str(path),
                        _target=self.target,
                    )
