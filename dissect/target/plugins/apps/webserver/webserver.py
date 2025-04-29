from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import NamespacePlugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

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

WebserverHostRecord = TargetRecordDescriptor(
    "application/log/webserver/host",
    [
        ("datetime", "ts"),
        ("string", "server_name"),
        ("varint", "server_port"),
        ("path", "root_path"),
        ("path", "access_log_config"),
        ("path", "error_log_config"),
        ("path", "source"),
    ],
)


class WebserverPlugin(NamespacePlugin):
    __namespace__ = "webserver"

    @export(record=[WebserverAccessLogRecord, WebserverErrorLogRecord])
    def logs(self) -> Iterator[WebserverAccessLogRecord | WebserverErrorLogRecord]:
        """Returns log file records from installed webservers."""
        yield from self.access()
        yield from self.error()
