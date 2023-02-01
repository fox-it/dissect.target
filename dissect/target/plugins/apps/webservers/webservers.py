from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

WebserverRecord = TargetRecordDescriptor(
    "application/log/webserver",
    [
        ("datetime", "ts"),
        ("string", "remote_user"),
        ("net.ipaddress", "remote_ip"),
        ("wstring", "url"),
        ("varint", "status_code"),
        ("varint", "bytes_sent"),
        ("wstring", "referer"),
        ("string", "useragent"),
        ("path", "source"),
    ],
)


class WebserverPlugin(Plugin):

    __namespace__ = "webserver"
    TOOLS = [
        "apache",
        "nginx",
        "iis",
        "caddy",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plugins = []
        for entry in self.TOOLS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:  # noqa
                target.log.exception(f"Failed to load tool plugin: {entry}")

    def check_compatible(self):
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible tool plugins found")

    def _func(self, f):
        for p in self._plugins:
            try:
                for entry in getattr(p, f)():
                    yield entry
            except Exception:
                self.target.log.exception(f"Failed to execute tool plugin: {p._name}{f}")

    @export(record=WebserverRecord)
    def history(self):
        """Returns history log file records from installed webservers (apache, caddy, iis and nginx)."""
        for record in self._func("history"):
            yield record
