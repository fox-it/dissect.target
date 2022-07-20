import datetime
import re

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

AuditRecord = TargetRecordDescriptor(
    "linux/log/audit",
    [
        ("datetime", "ts"),
        ("string", "type"),
        ("string", "id"),
        ("string", "msg"),
        ("string", "auditlog"),
    ],
)


class AuditPlugin(Plugin):
    def check_compatible(self):
        path = self.target.fs.path("/var/log/audit/")

        if path.exists():
            return True
        else:
            return False

    @export(record=[AuditRecord])
    def audit(self):
        """Return information stored in /var/log/audit.

        The audit log file on a Linux machine stores security-relevant information.
        Based on pre-configured rules.

        Sources:
            - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing
            - https://linux-audit.com/linux-audit-log-files-in-var-log-audit/
        """  # noqa: E501
        audit_type = re.compile(r"(?<=type=).+?\W")
        audit_msg = re.compile(r"(?<=\):\W).+")
        audit_meta = re.compile(r"(?<=msg=audit\().+?\)")

        for file in self.target.fs.listdir_ext("/var/log/audit"):
            fh = file.open("rt")

            for line in fh:
                # group returns the string representation of the match when using re.search
                _type = audit_type.search(line).group().strip(" ")
                msg = audit_msg.search(line).group()
                audit = audit_meta.search(line).group()
                ts, _id = audit.split(":")

                yield AuditRecord(
                    ts=datetime.datetime.fromtimestamp(float(ts)),
                    type=_type,
                    id=int(_id.strip(")")),
                    msg=msg,
                    auditlog=None,
                    _target=self.target,
                )
