from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.certificate import COMMON_CERTIFICATE_FIELDS
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import NamespacePlugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

WebserverAccessLogRecord = TargetRecordDescriptor(
    "application/webserver/log/access",
    [
        ("datetime", "ts"),
        ("string", "webserver"),
        ("string", "remote_user"),
        ("net.ipaddress", "remote_ip"),
        ("net.ipaddress", "local_ip"),
        ("varint", "pid"),
        ("string", "method"),
        ("uri", "uri"),
        ("string", "query"),
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
    "application/webserver/log/error",
    [
        ("datetime", "ts"),
        ("string", "webserver"),
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
    "application/webserver/host",
    [
        ("datetime", "ts"),
        ("string", "webserver"),
        ("string", "server_name"),
        ("varint", "server_port"),
        ("path", "root_path"),
        ("path", "access_log_config"),
        ("path", "error_log_config"),
        ("path", "tls_certificate"),
        ("path", "tls_key"),
        ("path", "source"),
    ],
)

WebserverCertificateRecord = TargetRecordDescriptor(
    "application/webserver/host/certificate",
    [
        ("datetime", "ts"),
        ("string", "webserver"),
        *COMMON_CERTIFICATE_FIELDS,
        ("string", "host"),
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
