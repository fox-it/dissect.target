import re

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

re_firewall = re.compile(r"(.*)=(.*)")


class FirewallPlugin(Plugin):
    """Plugin that parses firewall rules from the registry."""

    KEY = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
    FIELD_MAP = {"app": "uri"}
    VALUE_MAP = {"active": lambda val: val == "TRUE"}

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError(f"Registry key {self.KEY} not found")

    @export(record=DynamicDescriptor(["uri"]))
    def firewall(self):
        """Return firewall rules saved in the registry.

        For a Windows operating system, the Firewall rules are stored in the
        HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules registry key.

        Yields dynamic records with usually the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            key (string): The rule key name.
            version (string): The version field of the rule.
            action (string): The action of the rule.
            active (boolean): Whether the rule is active.
            dir (string): The direction of the rule.
            protocol (uint32): The specified protocol (UDP=17, TCP=6).
            lport (string): The listening port of the rule.
            rport (string): The receiving port of the rule.
            profile (string): The Profile field of the rule.
            app (string): The App field of the rule.
            svc (string): The Svc of the rule.
            name (string): The Name of the rule.
            desc (string): The Desc of the rule.
            embed_ctxt (string): The EmbedCtxt of the rule.
        """
        for reg in self.target.registry.keys(self.KEY):
            for entry in reg.values():
                r = [
                    ("string", "key"),
                    ("string", "version"),
                ]
                data = {}

                fields = entry.value.split("|")
                version = fields[0]
                for field in fields[1:-1]:
                    fname, value = re_firewall.search(field).groups()
                    fname = fname.lower()

                    ft = self.FIELD_MAP.get(fname, "string")
                    try:
                        value = self.VALUE_MAP[fname](value)
                    except Exception:  # noqa
                        pass

                    r.append((ft, fname))
                    data[fname] = value

                if "app" in data:
                    data["app"] = self.target.resolve(data["app"])

                yield TargetRecordDescriptor("windows/registry/firewall", r)(
                    key=entry.name,
                    version=version,
                    _target=self.target,
                    **data,
                )
