from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin
from dissect.target.helpers.record import TargetRecordDescriptor

RemoteAccessRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/log/remoteaccess",
    [
        ("datetime", "ts"),
        ("string", "tool"),
        ("path", "logfile"),
        ("string", "description"),
    ],
)
RemoteAccessIncomingConnectionRecord = TargetRecordDescriptor(
    "application/log/remoteaccess",
    [
        
        ("string", "tool"),
        ("path", "logfile"),
        ("string", "remote_tvid"),
        ("string", "tv_user_host"),
        ("string", "tv_user_host"),
        ("datetime", "start_time"),
        #("string","host"),
        ("datetime", "end_time"),
        ("string", "user_context"),
        ("string", "connection_type"),
        ("string", "connection_guid"),
    ],
)

class RemoteAccessPlugin(NamespacePlugin):
    """General Remote Access plugin.

    This plugin groups the functions of all remote access plugins. For example,
    instead of having to run both teamviewer.remoteaccess and anydesk.remoteaccess,
    you only have to run remoteaccess.remoteaccess to get output from both tools.
    """

    __namespace__ = "remoteaccess"
