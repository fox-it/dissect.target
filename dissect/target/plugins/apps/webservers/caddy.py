import re
from datetime import datetime

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord


class CaddyPlugin(plugin.Plugin):

    __namespace__ = "caddy"

    LOG_FILE_PATH = "/var/log/caddy_access.log"

    def __init__(self, target):
        super().__init__(target)

    @plugin.internal
    def get_log_path(self):

        log_file = self.target.fs.path(self.LOG_FILE_PATH)
        if log_file.exists():
            return log_file

        self.target.log.debug(f"Log files found in {self.LOG_FILE_PATH}")

        # Resolve configuration

        configuration_file = self.target.fs.path("/etc/caddy/Caddyfile")

        if configuration_file.exists():
            fh = configuration_file.open("r").readlines()

            for line in fh:
                line = line.strip()
                if "log  " in line:
                    log_file = self.target.fs.path(line.split(" ")[1]).parent

        if log_file.exists():
            return log_file

        return

    def check_compatible(self):
        if not self.target.fs.path(self.LOG_FILE_PATH).exists():
            raise UnsupportedPluginError("No caddy logs found")

    def parse_caddy_logs(self, entry):
        """Parses Caddy V1 logs in CRF format.
        Caddy V2 uses JSON logging and is not implemented (yet).
        """
        handle = entry.open()
        regex = re.compile(
            r'(?P<ipaddress>.*?) - - \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<statuscode>\d{3}) (?P<bytessent>\d+)'  # noqa: E501
        )

        def parse_datetime(date_str):
            # Example: 10/Apr/2020:14:10:12 +0000
            return datetime.strptime(f"{date_str}", "%d/%b/%Y:%H:%M:%S %z")

        for line in handle:
            line = line.rstrip()
            m = regex.match(line.decode())
            yield WebserverRecord(
                ts=parse_datetime(m.group("datetime")),
                ipaddr=m.group("ipaddress"),
                file_path=entry.resolve().__str__(),
                url=m.group("url"),
                statuscode=m.group("statuscode"),
                bytessent=m.group("bytessent"),
                _target=self.target,
            )

    @plugin.export(record=WebserverRecord)
    def history(self):
        log_path = self.get_log_path()
        yield from self.parse_caddy_logs(log_path)
