import re
from datetime import datetime

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, decompress_and_readlines
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord


class NginxPlugin(plugin.Plugin):
    __namespace__ = "nginx"
    LOGS_DIR_PATH = "/var/log/nginx"

    def __init__(self, target):
        super().__init__(target)

    @plugin.internal
    def get_log_paths(self):

        logs_dir = self.target.fs.path(self.LOGS_DIR_PATH)
        if logs_dir.exists():
            return [self.target.fs.path(p) for p in logs_dir.glob("access.log*")]

        self.target.log.debug(f"Log files found in {self.LOGS_DIR_PATH}")

        # Resolve configuration

        configuration_file = self.target.fs.path("/etc/nginx/nginx.conf")

        if configuration_file.exists():
            fh = configuration_file.open("r").readlines()

            for line in fh:
                line = line.strip()
                if "access_log" in line:
                    logs_dir = self.target.fs.path(line.split(" ")[1]).parent

        if logs_dir.exists():
            return [self.target.fs.path(p) for p in logs_dir.glob("access.log*")]

        return

    def check_compatible(self):
        if not self.target.fs.path(self.LOGS_DIR_PATH).exists():
            raise UnsupportedPluginError("No nginx logs found")

    def parse_nginx_logs(self, log_lines: [str], entry: TargetPath):
        regex = re.compile(
            r'(?P<ipaddress>.*?) - (?P<remote_user>.*?) \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<url>.*?)" (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<referer>(\-)|(.+))["]) "(?P<useragent>.*?)"',  # noqa: E501
            re.IGNORECASE,
        )

        def parse_datetime(date_str):
            # Example: 10/Apr/2020:14:10:12 +0000
            return datetime.strptime(f"{date_str}", "%d/%b/%Y:%H:%M:%S %z")

        for line in log_lines:
            m = regex.match(line)

            if not m:
                self.target.log.warning(f"No regex match found for Nginx log format for log line: {line}")
                return

            yield WebserverRecord(
                ts=parse_datetime(m.group("datetime")),
                ipaddr=m.group("ipaddress"),
                remote_user=m.group("remote_user"),
                file_path=entry.resolve().__str__(),
                url=m.group("url"),
                statuscode=m.group("statuscode"),
                bytessent=m.group("bytessent"),
                referer=m.group("referer"),
                useragent=m.group("useragent"),
                _target=self.target,
            )

    @plugin.export(record=WebserverRecord)
    def history(self):
        for path in self.get_log_paths():
            log_lines = [line.strip() for line in decompress_and_readlines(path)]
            yield from self.parse_nginx_logs(log_lines, path)
