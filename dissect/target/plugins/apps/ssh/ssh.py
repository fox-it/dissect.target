from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

OpenSSHUserRecordDescriptor = create_extended_descriptor([UserRecordDescriptorExtension])

COMMON_ELLEMENTS = [
    ("string", "key_type"),
    ("string", "comment"),
    ("path", "path"),
]

AuthorizedKeysRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/authorized_keys",
    [
        *COMMON_ELLEMENTS,
        ("string", "public_key"),
        ("string", "options"),
    ],
)


KnownHostRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/known_host",
    [
        ("datetime", "mtime_ts"),
        *COMMON_ELLEMENTS,
        ("string", "host"),
        ("varint", "port"),
        ("string", "public_key"),
        ("string", "marker"),
    ],
)


PrivateKeyRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/private_key",
    [
        ("datetime", "mtime_ts"),
        *COMMON_ELLEMENTS,
        ("string", "key_format"),
        ("string", "public_key"),
        ("boolean", "encrypted"),
    ],
)

PublicKeyRecord = OpenSSHUserRecordDescriptor(
    "application/openssh/public_key",
    [
        ("datetime", "mtime_ts"),
        *COMMON_ELLEMENTS,
        ("string", "public_key"),
    ],
)


class SSHPlugin(NamespacePlugin):
    __namespace__ = "ssh"
