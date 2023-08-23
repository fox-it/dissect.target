from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

RemoteAccessRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/log/remoteaccess",
    [
        ("datetime", "ts"),
        ("string", "tool"),
        ("path", "logfile"),
        ("string", "description"),
    ],
)


class RemoteAccessPlugin(NamespacePlugin):
    """General Remote Access plugin.

    This plugin groups the functions of all remote access plugins. For example,
    instead of having to run both teamviewer.remoteaccess and anydesk.remoteaccess,
    you only have to run remoteaccess.remoteaccess to get output from both tools.
    """

    __namespace__ = "remoteaccess"
