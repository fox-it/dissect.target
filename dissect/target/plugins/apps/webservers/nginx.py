import re
from datetime import datetime
from zoneinfo import ZoneInfo

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - (?P<remote_user>.*?) \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<referer>(\-)|(.+))["]) "(?P<useragent>.*?)"',  # noqa: E501
    re.IGNORECASE,
)


def parse_datetime(date_str: str, tz: ZoneInfo):
    # Example: 10/Apr/2020:14:10:12 +0000
    return datetime.strptime(f"{date_str}", "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tz)


class NginxPlugin(plugin.Plugin):
    __namespace__ = "nginx"

    def __init__(self, target):
        super().__init__(target)
        self.LOGS_DIR_PATH = self.get_log_paths()
        self.target_timezone = target.datetime.tzinfo

    @plugin.internal
    def get_log_paths(self):
        log_paths = []
        default_logs_dir = self.target.fs.path("/var/log/nginx")
        if default_logs_dir.exists():
            log_paths = [self.target.fs.path(p) for p in default_logs_dir.glob("access.log*")]

        # Check for custom paths in nginx install config
        if (config_file := self.target.fs.path("/etc/nginx/nginx.conf")).exists():
            lines = config_file.open("rt").readlines()
            for line in lines:
                line = line.strip()
                if "access_log" in line:
                    if (path := self.target.fs.path(line.split(" ")[1]).parent).exists():
                        log_paths.append(path)
                        break

        return log_paths

    def check_compatible(self):
        return len(self.LOGS_DIR_PATH) > 0

    @plugin.export(record=WebserverRecord)
    def logs(self):
        tzinfo = self.target.datetime.tzinfo

        for path in self.LOGS_DIR_PATH:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]

            for line in log_lines:
                match = LOG_REGEX.match(line)

                if not match:
                    self.target.log.warning("No regex match found for Nginx log format for log line '%s'", line)
                    continue

                match = match.groupdict()
                yield WebserverRecord(
                    ts=parse_datetime(match.get("datetime"), tzinfo),
                    remote_ip=match.get("remote_ip"),
                    remote_user=match.get("remote_user"),
                    url=match.get("url"),
                    status_code=match.get("status_code"),
                    bytes_sent=match.get("bytes_sent"),
                    referer=match.get("referer"),
                    useragent=match.get("useragent"),
                    source=path.resolve().__str__(),
                    _target=self.target,
                )
