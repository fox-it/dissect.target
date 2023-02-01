import re
from datetime import datetime
from zoneinfo import ZoneInfo

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - - \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<status_code>\d{3}) (?P<bytes_sent>\d+)'  # noqa: E501
)


def parse_datetime(date_str: str, tz: ZoneInfo):
    # Example: 10/Apr/2020:14:10:12 +0000
    return datetime.strptime(f"{date_str}", "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tz)


class CaddyPlugin(plugin.Plugin):

    __namespace__ = "caddy"

    def __init__(self, target):
        super().__init__(target)
        self.LOG_FILE_PATH = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self):
        log_paths = []
        default_log_file = self.target.fs.path("/var/log/caddy_access.log")
        if default_log_file.exists():
            log_paths.append(default_log_file)

        # Check for custom paths in Caddy config
        if (config_file := self.target.fs.path("/etc/caddy/Caddyfile")).exists():
            lines = config_file.open("rt").readlines()
            for line in lines:
                line = line.strip()
                if "log  " in line:
                    log_paths.append(self.target.fs.path(line.split(" ")[1]).parent)
                    break

        return log_paths

    def check_compatible(self):
        return self.target.fs.path(self.LOG_FILE_PATH).exists()

    @plugin.export(record=WebserverRecord)
    def logs(self):
        """Parses Caddy V1 logs in CRF format.

        Caddy V2 uses JSON logging when enabled (not by default) and is not implemented (yet).
        """
        tzinfo = self.target.datetime.tzinfo

        for path in self.LOGS_DIR_PATH:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]

            for line in log_lines:
                match = LOG_REGEX.match(line)

                if not match:
                    self.target.log.warning(
                        "Could match Caddy webserver log line with regex format for log line '%s'", line
                    )
                    continue

                match = match.groupdict()
                yield WebserverRecord(
                    ts=parse_datetime(match.get("datetime"), tzinfo),
                    remote_ip=match.get("remote_ip"),
                    url=match.get("url"),
                    status_code=match.get("status_code"),
                    bytes_sent=match.get("bytes_sent"),
                    source=path.resolve().__str__(),
                    _target=self.target,
                )
