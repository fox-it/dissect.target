import enum
import re
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

COMMON_REGEX = (
    r'(?P<remote_ip>.*?) (?P<remote_logname>.*?) (?P<remote_user>.*?) \[(?P<ts>.*)\] "(?P<url>.*?)" '
    r"(?P<status_code>\d{3}) (?P<bytes_sent>\d+)"
)
REFERER_USER_AGENT_REGEX = r'"(?P<referer>.*?)" "(?P<useragent>.*?)"'


class LogFormat(enum.Enum):
    VHOST_COMBINED = re.compile(rf"(?P<server_name>.*?):(?P<port>.*) {COMMON_REGEX} {REFERER_USER_AGENT_REGEX}")
    COMBINED = re.compile(rf"{COMMON_REGEX} {REFERER_USER_AGENT_REGEX}")
    COMMON = re.compile(COMMON_REGEX)


def infer_log_format(line: str) -> Optional[enum.Enum]:
    """Attempt to infer what standard LogFormat is used. Returns None if no known format can be inferred.

    Three default log type examples from Apache (note that the ipv4 could also be ipv6)::
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
        return LogFormat.VHOST_COMBINED
    elif line[-1:] == '"':
        # ends with a quotation mark, meaning three is a user agent
        return LogFormat.COMBINED
    elif line[-1:].isdigit():
        return LogFormat.COMMON
    return None


def parse_datetime(ts: str, tz: ZoneInfo) -> datetime:
    return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=tz)


class ApachePlugin(plugin.Plugin):
    """Apache log parsing plugin.

    Apache has three default log formats, which this plugin can all parse automatically. These are::
        LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
        LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
        LogFormat "%h %l %u %t \"%r\" %>s %O" common

    For the definitions of each format string, see https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats
    """

    __namespace__ = "apache"

    def __init__(self, target):
        super().__init__(target)
        self.LOGS_DIR_PATH = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self) -> []:
        default_logs_dir = "/var/log/apache2"
        return list(self.target.fs.path(default_logs_dir).glob("access.log*"))

    def check_compatible(self):
        return len(self.LOGS_DIR_PATH) > 0

    @plugin.export(record=WebserverRecord)
    def history(self):
        tzinfo = self.target.datetime.tzinfo

        for path in self.LOGS_DIR_PATH:
            log_lines = [line.strip() for line in open_decompress(path, "rt")]
            for line in log_lines:
                if not line:
                    continue

                regex = infer_log_format(line)
                if not regex:
                    self.target.log.warning("Apache log format could not be inferred for log line '%s'", line)
                    continue

                match = regex.value.match(line)
                if not match:
                    self.target.log.warning(
                        "No regex match found for Apache log format %s for log line: %s", regex, line
                    )
                    continue

                match = match.groupdict()
                yield WebserverRecord(
                    ts=parse_datetime(match.get("ts"), tzinfo),
                    remote_user=match.get("remote_user"),
                    remote_ip=match.get("remote_ip"),
                    url=match.get("url"),
                    status_code=match.get("status_code"),
                    bytes_sent=match.get("bytes_sent"),
                    referer=match.get("referer"),
                    useragent=match.get("useragent"),
                    source=path.resolve().__str__(),
                )
