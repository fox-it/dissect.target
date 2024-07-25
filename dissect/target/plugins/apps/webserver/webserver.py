from typing import Iterator, Union

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import NamespacePlugin, export

WebserverAccessLogRecord = TargetRecordDescriptor(
    "application/log/webserver/access",
    [
        ("datetime", "ts"),
        ("string", "remote_user"),
        ("net.ipaddress", "remote_ip"),
        ("net.ipaddress", "local_ip"),
        ("varint", "pid"),
        ("string", "method"),
        ("uri", "uri"),
        ("string", "protocol"),
        ("varint", "status_code"),
        ("varint", "bytes_sent"),
        ("uri", "referer"),
        ("string", "useragent"),
        ("varint", "response_time_ms"),
        ("path", "source"),
    ],
)

WebserverErrorLogRecord = TargetRecordDescriptor(
    "application/log/webserver/error",
    [
        ("datetime", "ts"),
        ("net.ipaddress", "remote_ip"),
        ("varint", "pid"),
        ("string", "module"),
        ("string", "level"),
        ("string", "error_source"),
        ("string", "error_code"),
        ("string", "message"),
        ("path", "source"),
    ],
)


class WebserverPlugin(NamespacePlugin):
    __namespace__ = "webserver"

    @export(record=[WebserverAccessLogRecord, WebserverErrorLogRecord])
    def logs(self) -> Iterator[Union[WebserverAccessLogRecord, WebserverErrorLogRecord]]:
        """Returns log file records from installed webservers."""
        yield from self.access()
        yield from self.error()
