from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

WebserverRecord = TargetRecordDescriptor(
    "application/log/webserver",
    [
        ("datetime", "ts"),
        ("string", "remote_user"),
        ("net.ipaddress", "remote_ip"),
        ("uri", "url"),
        ("varint", "status_code"),
        ("varint", "bytes_sent"),
        ("uri", "referer"),
        ("string", "useragent"),
        ("path", "source"),
    ],
)


class WebserverPlugin(Plugin):
    __namespace__ = "webserver"
    WEBSERVERS = [
        "apache",
        "nginx",
        "iis",
        "caddy",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self._plugins = []
        for entry in self.WEBSERVERS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:  # noqa
                target.log.exception("Failed to load webserver plugin: %s", entry)

    def check_compatible(self) -> bool:
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible tool plugins found")

    def _func(self, f: str) -> Iterator[WebserverRecord]:
        for p in self._plugins:
            try:
                yield from getattr(p, f)()
            except Exception:
                self.target.log.exception("Failed to execute webserver plugin: %s.%s", p._name, f)

    @export(record=WebserverRecord)
    def logs(self) -> Iterator[WebserverRecord]:
        """Returns log file records from installed webservers."""
        yield from self.access()
        # TODO: In the future we should add error logs too.

    @export(record=WebserverRecord)
    def access(self) -> Iterator[WebserverRecord]:
        """Returns access.log records from installed webservers."""
        for record in self._func("access"):
            yield record
