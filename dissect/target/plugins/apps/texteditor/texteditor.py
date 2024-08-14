from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

GENERIC_TAB_CONTENTS_RECORD_FIELDS = [("string", "content"), ("path", "path"), ("string", "deleted_content")]

TexteditorTabContentRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)


class TexteditorPlugin(NamespacePlugin):
    __namespace__ = "texteditor"
