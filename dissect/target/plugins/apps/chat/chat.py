from __future__ import annotations

from typing import Union

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

COMMON_FIELDS = [
    ("datetime", "ts"),
    ("string", "client"),
    ("string", "account"),
    ("string", "sender"),
    ("string", "recipient"),
]

GENERIC_USER_FIELDS = [
    ("datetime", "ts_mtime"),
    ("string", "client"),
    ("string", "account"),
]

GENERIC_ATTACHMENT_FIELDS = [
    *COMMON_FIELDS,
    ("path", "attachment"),
    ("string", "description"),
]

GENERIC_MESSAGE_FIELDS = [
    *COMMON_FIELDS,
    ("string", "message"),
]

ChatUserRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "chat/user",
    GENERIC_USER_FIELDS,
)

ChatMessageRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "chat/message",
    GENERIC_MESSAGE_FIELDS,
)

ChatAttachmentRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "chat/attachment",
    GENERIC_ATTACHMENT_FIELDS,
)

ChatRecord = Union[ChatUserRecord, ChatMessageRecord, ChatAttachmentRecord]


class ChatPlugin(NamespacePlugin):
    __namespace__ = "chat"
