import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord
from dissect.target.target import Target

LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - (?P<remote_user>.*?) \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<referer>(\-)|(.+))["]) "(?P<useragent>.*?)"',  # noqa: E501
    re.IGNORECASE,
)


class NginxPlugin(plugin.Plugin):
    __namespace__ = "nginx"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        log_paths = []
        default_logs_dir = self.target.fs.path("/var/log/nginx")
        if default_logs_dir.exists():
            log_paths = [self.target.fs.path(p) for p in default_logs_dir.glob("access.log*")]

        # Check for custom paths in nginx install config
        if (config_file := self.target.fs.path("/etc/nginx/nginx.conf")).exists():
            for line in config_file.open("rt"):
                line = line.strip()
                if "access_log" in line:
                    if (path := self.target.fs.path(line.split(" ")[1]).parent).exists():
                        log_paths.append(path)
                        break

        return log_paths

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @plugin.export(record=WebserverRecord)
    def access(self) -> Iterator[WebserverRecord]:
        tzinfo = self.target.datetime.tzinfo

        for path in self.log_paths:
            for line in open_decompress(path, "rt"):
                line = line.strip()
                if not line:
                    continue

                match = LOG_REGEX.match(line)
                if not match:
                    self.target.log.warning("No regex match found for Nginx log format for log line '%s'", line)
                    continue

                match = match.groupdict()
                yield WebserverRecord(
                    ts=datetime.strptime(match["datetime"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tzinfo),
                    remote_ip=match["remote_ip"],
                    remote_user=match["remote_user"],
                    url=match["url"],
                    status_code=match["status_code"],
                    bytes_sent=match["bytes_sent"],
                    referer=match["referer"],
                    useragent=match["useragent"],
                    source=path.resolve(),
                    _target=self.target,
                )
