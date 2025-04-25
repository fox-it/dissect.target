from __future__ import annotations

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

GENERIC_LOG_RECORD_FIELDS = [
    ("datetime", "ts"),
    ("string", "message"),
    ("path", "source"),
]

GENERIC_FILE_TRANSFER_RECORD_FIELDS = [
    ("datetime", "ts"),
    ("path", "filename"),
    ("string", "message"),
    ("path", "source"),
]

RemoteAccessLogRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "remoteaccess/log", GENERIC_LOG_RECORD_FIELDS
)

RemoteAccessFileTransferRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "remoteaccess/filetransfer", GENERIC_FILE_TRANSFER_RECORD_FIELDS
)


class RemoteAccessPlugin(NamespacePlugin):
    """General Remote Access plugin.

    This plugin groups the functions of all remote access plugins. For example,
    instead of having to run both teamviewer.remoteaccess and anydesk.remoteaccess,
    you only have to run remoteaccess.remoteaccess to get output from both tools.
    """

    __namespace__ = "remoteaccess"
