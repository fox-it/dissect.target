import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from defusedxml import ElementTree
from flow.record.base import RE_VALID_FIELD_NAME

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugins.apps.webservers.webservers import WebserverAccessLogRecord

LOG_RECORD_NAME = "filesystem/windows/iis/logs"

BASIC_RECORD_FIELDS = [
    ("datetime", "ts"),
    ("net.ipaddress", "client_ip"),
    ("net.ipaddress", "server_ip"),
    ("string", "username"),
    ("string", "server_name"),
    ("string", "site_name"),
    ("string", "request_method"),
    ("string", "request_path"),
    ("string", "request_query"),
    ("string", "request_size_bytes"),
    ("string", "response_size_bytes"),
    ("string", "process_time_ms"),
    # https://docs.microsoft.com/en-US/troubleshoot/iis/http-status-code
    ("string", "service_status_code"),
    # https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes?redirectedfrom=MSDN#system-error-codes-1
    ("string", "win32_status_code"),
    ("string", "log_format"),
    ("string", "log_file"),
]
BasicRecordDescriptor = TargetRecordDescriptor(LOG_RECORD_NAME, BASIC_RECORD_FIELDS)

# Simplified reverse of flow.record.base.RE_VALID_FIELD_NAME
FIELD_NAME_INVALID_CHARS_RE = re.compile(r"[^a-zA-Z0-9]")


class IISLogsPlugin(plugin.Plugin):
    """IIS 7 (and above) logs plugin.

    References:
        - https://docs.microsoft.com/en-us/iis/get-started/planning-your-iis-architecture/introduction-to-applicationhostconfig
        - https://docs.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525807(v=vs.90)
    """  # noqa: E501

    APPLICATION_HOST_CONFIG = "sysvol/windows/system32/inetsrv/config/applicationHost.config"

    __namespace__ = "iis"

    def __init__(self, target):
        super().__init__(target)
        self.config = self.target.fs.path(self.APPLICATION_HOST_CONFIG)

    def check_compatible(self) -> None:
        if not self.config.exists():
            raise UnsupportedPluginError("No ApplicationHost config file found")

    @plugin.internal
    def get_log_dirs(self) -> list[tuple[str, str]]:
        try:
            xml_data = ElementTree.fromstring(self.config.open().read(), forbid_dtd=True)
        except ElementTree.ParseError as e:
            self.target.log.warning(f"Error while parsing {self.config}: {e}")
            return []

        log_paths = []

        for log_file_element in xml_data.findall("*/sites/*/logFile"):
            log_format = log_file_element.get("logFormat") or "W3C"
            log_dir = log_file_element.get("directory")
            log_dir = self.target.resolve(log_dir)
            log_paths.append((log_format, log_dir))

        return log_paths

    @plugin.internal
    def iter_log_format_path_pairs(self) -> list[tuple[str, str]]:
        for log_format, log_dir_path in self.get_log_dirs():
            for log_file in self.iter_log_paths(log_dir_path):
                yield (log_format, log_file)

    @plugin.internal
    def parse_iis_format_log(self, path: Path) -> Iterator[BasicRecordDescriptor]:
        """Parse log file in IIS format and stream log records.

        This format is not the default IIS log format.

        References:
            - https://docs.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525807(v=vs.90)#iis-log-file-format
            - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc728311(v=ws.10)
            - https://learn.microsoft.com/en-us/iis/configuration/system.applicationHost/sites/site/logFile/#attributes-logFormat-IIS
        """  # noqa: E501

        tzinfo = self.target.datetime.tzinfo

        def parse_datetime(date_str: str, time_str: str) -> datetime:
            # Example: 10/1/2021 7:19:59
            # "time is recorded as local time." [^3]
            return datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S").replace(tzinfo=tzinfo)

        for line in path.open().readlines():
            # even though the docs say that IIS log format is ASCII format,
            # it is possible to select UTF-8 in configuration
            line = line.decode("utf-8", errors="backslashreplace")

            # Example:
            # 127.0.0.1, -, 9/20/2021, 8:51:21, W3SVC1, DESKTOP-PJOQLJS, 127.0.0.1, 0, 691, 5005, 404, 2, GET, /some, -,
            parts = [part.strip() for part in line.strip().split(",")]

            if len(parts) != 16:
                self.target.log.debug('Unrecognised log line format, skipping: "%s"', line)
                continue

            row = {
                "log_file": str(path),
                "log_format": "IIS",
                "ts": parse_datetime(parts[2], parts[3]),
                "client_ip": parts[0],
                "username": parts[1],
                "site_name": parts[4],
                "server_name": parts[5],
                "server_ip": parts[6],
                "process_time_ms": parts[7],
                "request_size_bytes": parts[8],
                "response_size_bytes": parts[9],
                "service_status_code": parts[10],
                "win32_status_code": parts[11],
                "request_method": parts[12],
                "request_path": parts[13],
                "request_query": parts[14],
                "_target": self.target,
            }
            row = replace_dash_with_none(row)
            yield BasicRecordDescriptor(**row)

    @lru_cache(maxsize=4096)
    def _create_extended_descriptor(self, extra_fields: tuple[tuple[str, str]]) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(LOG_RECORD_NAME, BASIC_RECORD_FIELDS + list(extra_fields))

    @plugin.internal
    def parse_w3c_format_log(self, path: Path) -> Iterator[TargetRecordDescriptor]:
        """Parse log file in W3C format and stream log records.

        This is the default logging format for IIS [^3].

        References:
            - https://docs.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525807(v=vs.90)#w3c-extended-log-file-format
            - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786596(v=ws.10)
            - https://learn.microsoft.com/en-us/iis/configuration/system.applicationHost/sites/site/logFile/#attributes-logFormat-W3C
        """  # noqa: E501

        basic_fields = {
            "c-ip",
            "s-ip",
            "cs-username",
            "s-computername",
            "s-sitename",
            "cs-method",
            "cs-uri-stem",
            "cs-uri-query",
            "cs-bytes",
            "sc-bytes",
            "time-taken",
            "sc-status",
            "sc-win32-status",
        }

        record_descriptor = None
        fields = []
        extra_fields = []
        for line in path.open().readlines():
            line = line.decode("utf-8", errors="backslashreplace").strip()

            if line.startswith("#Fields"):
                _, _, fields_str = line.partition("Fields: ")
                fields = fields_str.split()
                extra_fields = sorted(set(fields) - basic_fields)
                extra_fields_with_types = [("string", normalise_field_name(f)) for f in extra_fields]
                record_descriptor = self._create_extended_descriptor(tuple(extra_fields_with_types))
                continue
            elif line.startswith("#"):
                continue

            values = line.split()

            if len(values) != len(fields):
                self.target.log.warning('Log values do not match fields defined, skipping: "%s"', line)
                continue

            if not record_descriptor:
                self.target.log.warning(
                    'Comment line with the fields defined should come before the values, skipping: "%s"', line
                )

            raw = replace_dash_with_none(dict(zip(fields, values)))

            # Example:
            # {
            #     "c-ip": "127.0.0.1",
            #     "cs(Cookie)": null,
            #     "cs(Referer)": null,
            #     "cs(User-Agent)": "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52",  # noqa: E501
            #     "cs-bytes": "714",
            #     "cs-host": "127.0.0.1",
            #     "cs-method": "GET",
            #     "cs-uri-query": null,
            #     "cs-uri-stem": "/nonexistent-path/path+path2",
            #     "cs-username": null,
            #     "cs-version": "HTTP/1.1",
            #     "custom-field-1": null,
            #     "custom-field-2": "Cache-Control:+max-age=0++Connection:+keep-alive++Accept:+text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9++Accept-Encoding:+gzip,+deflate,+br++Accept-Language:+en-US,en;q=0.9++Host:+127.0.0.1++User-Agent:+Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/93.0.4577.82+Safari/537.36+Edg/93.0.961.52++sec-ch-ua:+\"Microsoft+Edge\";v=\"93\",+\"+Not;A+Brand\";v=\"99\",+\"Chromium\";v=\"93\"++sec-ch-ua-mobile:+?0++sec-ch-ua-platform:+\"Windows\"++Upgrade-Insecure-Requests:+1++Sec-Fetch-Site:+none++Sec-Fetch-Mode:+navigate++Sec-Fetch-User:+?1++Sec-Fetch-Dest:+document++",  # noqa: E501
            #     "date": "2021-10-01",
            #     "s-computername": "DESKTOP-PJOQLJS",
            #     "s-ip": "127.0.0.1",
            #     "s-port": "80",
            #     "s-sitename": "W3SVC1",
            #     "sc-bytes": "5143",
            #     "sc-status": "404",
            #     "sc-substatus": "11",
            #     "sc-win32-status": "0",
            #     "time": "18:03:57",
            #     "time-taken": "1"
            # }

            # Make the datetime timezone aware.
            # "the time stamp for each W3C Extended Logging log record is UTC-based." [^3]
            ts = None
            if raw.get("date") and raw.get("time"):
                ts = datetime.strptime(f"{raw['date']} {raw['time']}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

            yield record_descriptor(
                ts=ts,
                client_ip=raw.get("c-ip"),
                server_ip=raw.get("s-ip"),
                username=raw.get("cs-username"),
                server_name=raw.get("s-computername"),
                site_name=raw.get("s-sitename"),
                request_method=raw.get("cs-method"),
                request_path=raw.get("cs-uri-stem"),
                request_query=raw.get("cs-uri-query"),
                request_size_bytes=raw.get("cs-bytes"),
                response_size_bytes=raw.get("sc-bytes"),
                process_time_ms=raw.get("time-taken"),
                service_status_code=raw.get("sc-status"),
                win32_status_code=raw.get("sc-win32-status"),
                log_format="W3C",
                log_file=str(path),
                _target=self.target,
                **{normalise_field_name(field): raw.get(field) for field in extra_fields},
            )

    @plugin.internal
    def iter_log_paths(self, log_dir: str) -> Iterator[Path]:
        log_dir = fsutil.normalize(log_dir, alt_separator=self.target.fs.alt_separator)
        yield from self.target.fs.path(log_dir).glob("*/*.log")

    @plugin.export(record=BasicRecordDescriptor)
    def logs(self) -> Iterator[TargetRecordDescriptor]:
        """Return contents of IIS (v7 and above) log files.

        Internet Information Services (IIS) for Windows Server is a manageable web server for hosting anything on the
        web. Logs files might, for example, contain traces that indicate that the web server has been exploited.
        Supported log formats: IIS, W3C.
        """
        for log_format, log_file in self.iter_log_format_path_pairs():
            if log_format == "IIS":
                parse_func = self.parse_iis_format_log
            elif log_format == "W3C":
                parse_func = self.parse_w3c_format_log
            else:
                raise ValueError(f"Unsupported IIS log format: {log_format}")

            self.target.log.info("Parsing IIS log file %s in %s format", log_file, log_format)
            yield from parse_func(log_file)

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of IIS (v7 and above) log files in unified WebserverAccessLogRecord format.

        See function ``iis.logs`` for more information and more verbose IIS records.
        """

        for iis_record in self.logs():
            yield WebserverAccessLogRecord(
                ts=iis_record.ts,
                remote_user=iis_record.username,
                remote_ip=iis_record.client_ip,
                method=iis_record.request_method,
                uri=iis_record.request_path,
                protocol=getattr(iis_record, "cs_version", None),
                status_code=getattr(iis_record, "service_status_code", None),
                bytes_sent=iis_record.response_size_bytes,
                referer=getattr(iis_record, "cs_referer", None),
                useragent=getattr(iis_record, "cs_user_agent", None),
                source=iis_record.log_file,
                _target=self.target,
            )


def replace_dash_with_none(data: dict) -> dict:
    """Replace "-" placeholder in dict values with None"""
    return {k: (None if v == "-" else v) for k, v in data.items()}


def normalise_field_name(field: str) -> str:
    """Replace all character that are not allowed in the field name by flow.record
    with _, and strip all hanging _ from start / end of the string.
    """
    if RE_VALID_FIELD_NAME.match(field):
        return field

    field = FIELD_NAME_INVALID_CHARS_RE.sub("_", field).strip("_").lower()
    return field
