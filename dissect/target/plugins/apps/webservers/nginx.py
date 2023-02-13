import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dissect.target import plugin
from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverAccessLogRecord
from dissect.target.target import Target

LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - (?P<remote_user>.*?) \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<method>.*?) (?P<uri>.*?) ?(?P<protocol>HTTP\/.*?)?" (?P<status_code>\d{3}) (?P<bytes_sent>-|\d+) (["](?P<referer>(\-)|(.+))["]) "(?P<useragent>.*?)"',  # noqa: E501
)


class NginxPlugin(plugin.Plugin):
    __namespace__ = "nginx"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        log_paths = []

        # Add any well known default Caddy log locations
        log_paths.extend(self.target.fs.path("/var/log/nginx").glob("access.log*"))

        # Check for custom paths in nginx install config
        if (config_file := self.target.fs.path("/etc/nginx/nginx.conf")).exists():
            for line in config_file.open("rt"):
                line = line.strip()
                if "access_log " in line:
                    try:
                        path = self.target.fs.path(line.split()[1])
                        log_paths.extend(p for p in path.parent.glob(path.name + "*") if p not in log_paths)
                    except IndexError:
                        self.target.log.warning("Unexpected NGINX log configuration: %s (%s)", line, path)

        return log_paths

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of NGINX access log files in unified WebserverAccessLogRecord format."""

        for path in self.log_paths:
            try:
                path = path.resolve(strict=True)
                for line in open_decompress(path, "rt"):
                    line = line.strip()
                    if not line:
                        continue

                    match = LOG_REGEX.match(line)
                    if not match:
                        self.target.log.warning("Could not match NGINX regex format for log line: %s (%s)", line, path)
                        continue

                    log = match.groupdict()
                    yield WebserverAccessLogRecord(
                        ts=datetime.strptime(log["datetime"], "%d/%b/%Y:%H:%M:%S %z"),
                        remote_ip=log["remote_ip"],
                        remote_user=log["remote_user"],
                        method=log["method"],
                        uri=log["uri"],
                        protocol=log["protocol"],
                        status_code=log["status_code"],
                        bytes_sent=log["bytes_sent"].strip("-") or 0,
                        referer=log["referer"],
                        useragent=log["useragent"],
                        source=path,
                        _target=self.target,
                    )
            except FileNotFoundError:
                self.target.log.warning("NGINX log file configured but could not be found (dead symlink?): %s", path)
            except Exception as e:
                self.target.log.warning("An error occured parsing NGINX log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)
