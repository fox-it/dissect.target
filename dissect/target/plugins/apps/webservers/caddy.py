import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from datetime import datetime, timezone

from dissect.target import plugin
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord


class CaddyPlugin(plugin.Plugin):

    __namespace__ = "caddy"

    def __init__(self, target):
        super().__init__(target)

        self.LOG_FILE_PATH = self.get_log_path()
        self.target_timezone = target.datetime.tzinfo

    @plugin.internal
    def get_log_path(self):

        # Try the default log location
        log_file = "/var/log/caddy_access.log"
        if log_file.exists():
            self.target.log.debug(f"Log file found at {self.LOG_FILE_PATH}")
            return log_file

        # Resolve configuration
        configuration_file = self.target.fs.path("/etc/caddy/Caddyfile")
        if not configuration_file.exists():
            return False

        fh = configuration_file.open("r").readlines()

        for line in fh:
            line = line.strip()
            if "log  " in line:
                log_file = self.target.fs.path(line.split(" ")[1]).parent
                break

        if log_file.exists():
            self.target.log.debug(f"Log files found in {log_file}")
            return log_file

    def check_compatible(self):
        return self.target.fs.path(self.LOG_FILE_PATH).exists()

    def parse_caddy_logs(self, entry):
        """Parses Caddy V1 logs in CRF format.
        Caddy V2 uses JSON logging when enabled (not by default) and is not implemented (yet).
        """
        handle = entry.open()
        regex = re.compile(
            r'(?P<ipaddress>.*?) - - \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<statuscode>\d{3}) (?P<bytessent>\d+)'  # noqa: E501
        )

        def parse_datetime(date_str, tz):
            # Example: 10/Apr/2020:14:10:12 +0000
            return datetime.strptime(f"{date_str}", "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tz)

        for line in handle:
            line = line.rstrip()
            m = regex.match(line.decode())

            if not m:
                self.target.log.warning(
                    f"Could match Caddy webserver log line with regex format in {self.LOG_FILE_PATH}"
                )
                continue

            yield WebserverRecord(
                ts=parse_datetime(m.group("datetime"), self.target_timezone),
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
