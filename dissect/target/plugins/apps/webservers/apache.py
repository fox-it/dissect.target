import re
from datetime import datetime, timezone
from typing import Iterator, Optional

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

COMMON_REGEX = (
    r'(?P<ipaddr>.*?) (?P<remote_logname>.*?) (?P<remote_user>.*?) \[(?P<ts>.*)\] "(?P<url>.*?)" '
    r"(?P<statuscode>\d{3}) (?P<bytessent>\d+)"
)
REFERER_USER_AGENT_REGEX = r'"(?P<referer>.*?)" "(?P<useragent>.*?)"'
LOG_FORMATS = {
    "vhost_combined": re.compile(rf"(?P<server_name>.*?):(?P<port>.*) {COMMON_REGEX} {REFERER_USER_AGENT_REGEX}"),
    "combined": re.compile(rf"{COMMON_REGEX} {REFERER_USER_AGENT_REGEX}"),
    "common": re.compile(rf"{COMMON_REGEX}"),
}


def infer_log_format(line: str) -> Optional[str]:
    """
    Infers - based on the format of the log - what standard LogFormat it is. If none can be inferred, returns none.

    Three default log type examples from Apache (note that the ipv4 could also be ipv6):
    combined       = '1.2.3.4 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0
                      (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0
                      Safari/537.36"'
    common         = '1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
    vhost_combined = 'example.com:80 1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 "-"
                      "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko)
                      Chrome/108.0.0.0 Safari/537.36"'
    """

    first_part = line.split(" ")[0]
    if ":" in first_part and "." in first_part:
        # does not start with IP, hence it must be a vhost typed log
        return "vhost_combined"
    elif line[-1:] == '"':
        # ends with a quotation mark, meaning three is a user agent
        return "combined"
    elif line[-1:].isdigit():
        return "common"
    return None


class ApachePlugin(plugin.Plugin):
    """
    Apache has three default log formats, which this plugin can all parse automatically. These are:
    LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
    LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %O" common

    For the definitions of each format string, see https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats
    """

    __namespace__ = "apache"
    LOGS_DIR_PATH = "/var/log/apache2"

    @plugin.internal
    def get_log_paths(self) -> []:
        logs_dir = self.target.fs.path(self.LOGS_DIR_PATH)
        if logs_dir.exists():
            self.target.log.debug(f"Log files found in {self.LOGS_DIR_PATH}")
            return [self.target.fs.path(p) for p in logs_dir.glob("access.log*")]
        return []

    def check_compatible(self):
        log_paths = self.get_log_paths()
        if len(log_paths) == 0:
            raise UnsupportedPluginError("No apache log files found")

    def parse_log(self, line: str, log_format: str) -> Optional[WebserverRecord]:
        regex = LOG_FORMATS[log_format]
        match = regex.match(line)

        if not match:
            self.target.log.warning(f"No regex match found for Apache log format {log_format} for log line: {line}")
            return

        match = match.groupdict()
        return WebserverRecord(
            ts=self.parse_datetime(match.get("ts")),
            remote_user=match.get("remote_user"),
            ipaddr=match.get("ipaddr"),
            url=match.get("url"),
            statuscode=match.get("statuscode"),
            bytessent=match.get("bytessent"),
            referer=match.get("referer"),
            useragent=match.get("useragent"),
        )

    @staticmethod
    def parse_datetime(ts: str) -> datetime:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=timezone.utc)

    def parse_logs(self, log_lines: [str], path: TargetPath) -> Iterator[Optional[WebserverRecord]]:
        for line in log_lines:
            if not line or line == "":
                continue

            log_format = infer_log_format(line)

            if not log_format:
                self.target.log.warning(f"Apache log format could not be inferred for log line '{line}'")

            record = self.parse_log(line, log_format)
            if not record:
                yield None

            record.file_path = path.resolve().__str__()
            yield record

    @plugin.export(record=WebserverRecord)
    def history(self):
        for path in self.get_log_paths():
            log_lines = [line.strip() for line in open_decompress(path, "rt")]
            yield from self.parse_logs(log_lines, path)
