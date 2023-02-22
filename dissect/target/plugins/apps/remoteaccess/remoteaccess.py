from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

RemoteAccessRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/log/remoteaccess",
    [
        ("datetime", "ts"),
        ("string", "tool"),
        ("uri", "logfile"),
        ("string", "description"),
    ],
)


class RemoteAccessPlugin(Plugin):
    """General Remote Access plugin.

    This plugin groups the functions of all remote access plugins. For example,
    instead of having to run both teamviewer.remoteaccess and anydesk.remoteaccess,
    you only have to run remoteaccess.remoteaccess to get output from both tools.
    """

    __namespace__ = "remoteaccess"
    TOOLS = [
        "teamviewer",
        "anydesk",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plugins = []
        for entry in self.TOOLS:
            try:
                self._plugins.append(getattr(self.target, entry))
            except Exception:  # noqa
                target.log.exception("Failed to load tool plugin: %s", entry)

    def check_compatible(self):
        if not len(self._plugins):
            raise UnsupportedPluginError("No compatible tool plugins found")

    def _func(self, f):
        for p in self._plugins:
            try:
                for entry in getattr(p, f)():
                    yield entry
            except Exception:
                self.target.log.exception("Failed to execute tool plugin: {}.{}", p._name, f)

    @export(record=RemoteAccessRecord)
    def remoteaccess(self):
        """Return Remote Access records from all Remote Access Tools.

        This plugin groups the functions of all remote access plugins. For example, instead of having to run both
        teamviewer.remoteaccess and anydesk.remoteaccess, you only have to run remoteaccess.remoteaccess to get output
        from both tools.

        Yields RemoteAccessRecords with the following fields:
           ('string', 'hostname'),
           ('string', 'domain'),
           ('datetime', 'ts'),
           ('string', 'user'),
           ('string', 'tool'),
           ('uri', 'logfile'),
           ('string', 'description')
        """
        for e in self._func("remoteaccess"):
            yield e
