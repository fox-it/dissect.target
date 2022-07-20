import re

from dissect.target.plugin import export
from dissect.target.plugins.os.unix._os import LinuxPlugin


class DebianPlugin(LinuxPlugin):
    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/etc/network/interfaces"):
                return fs

        return None

    @export(property=True)
    def ips(self):
        fh = self.target.fs.open("/etc/network/interfaces")
        d = {}

        interfaces = []

        for line in fh:
            line_split = re.split(r"\s+", line.strip())
            if line_split[0] == "iface":
                if d:
                    interfaces.append(d)

                d = {"interface": line_split[1]}

            d[line_split[0]] = line_split[1:]

        if d:
            interfaces.append(d)

        r = set()

        for d in interfaces:
            if "address" not in d:
                continue

            r.add(d["address"][0])

        return list(r)
