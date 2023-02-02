import re
from datetime import datetime
from zoneinfo import ZoneInfo

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - - \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<status_code>\d{3}) (?P<bytes_sent>\d+)'  # noqa: E501
)


class CaddyPlugin(plugin.Plugin):

    __namespace__ = "caddy"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        log_paths = []
        default_log_file = self.target.fs.path("/var/log/caddy_access.log")
        if default_log_file.exists():
            log_paths.append(default_log_file)

        # Check for custom paths in Caddy config
        if (config_file := self.target.fs.path("/etc/caddy/Caddyfile")).exists():
            for line in config_file.open("rt"):
                line = line.strip()
                if "log  " in line:
                    if (path := self.target.fs.path(line.split(" ")[1]).parent).exists():
                        log_paths.append(path)
                        break

        return log_paths

    def check_compatible(self) -> bool:
        return self.target.fs.path(self.LOG_FILE_PATH).exists()

    @plugin.export(record=WebserverRecord)
    def access(self) -> Iterator[WebserverRecord]:
        """Parses Caddy V1 logs in CRF format.

        Caddy V2 uses JSON logging when enabled (not by default) and is not implemented (yet).
        """
        tzinfo = self.target.datetime.tzinfo

        for path in self.log_paths:
            for line in open_decompress(path, "rt"):
                line = line.strip()
                if not line:
                    continue
                match = LOG_REGEX.match(line)

                if not match:
                    self.target.log.warning(
                        "Could match Caddy webserver log line with regex format for log line '%s'", line
                    )
                    continue

                match = match.groupdict()
                yield WebserverRecord(
                    ts=datetime.strptime(match.get("datetime"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tzinfo),
                    remote_ip=match.get("remote_ip"),
                    url=match.get("url"),
                    status_code=match.get("status_code"),
                    bytes_sent=match.get("bytes_sent"),
                    source=path.resolve(),
                    _target=self.target,
                )
