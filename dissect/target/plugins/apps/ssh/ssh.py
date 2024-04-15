import base64
from hashlib import md5, sha1, sha256

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
        ("digest", "fingerprint"),
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
        ("digest", "fingerprint"),
    ],
)


class SSHPlugin(NamespacePlugin):
    __namespace__ = "ssh"


def calculate_fingerprints(public_key_decoded: bytes, ssh_keygen_format: bool = False) -> tuple[str, str, str]:
    """Calculate the MD5, SHA1 and SHA256 digest of the given decoded public key.

    Adheres as much as possible to the output provided by ssh-keygen when ``ssh_keygen_format``
    parameter is set to ``True``. When set to ``False`` (default) hexdigests are calculated
    instead for ``sha1``and ``sha256``.

    Resources:
        - https://en.wikipedia.org/wiki/Public_key_fingerprint
        - https://man7.org/linux/man-pages/man1/ssh-keygen.1.html
        - ``ssh-keygen -l -E <alg> -f key.pub``
    """
    if not public_key_decoded:
        raise ValueError("No decoded public key provided")

    if not isinstance(public_key_decoded, bytes):
        raise ValueError("Provided public key should be bytes")

    if public_key_decoded[0:3] != b"\x00\x00\x00":
        raise ValueError("Provided value does not look like a public key")

    digest_md5 = md5(public_key_decoded).digest()
    digest_sha1 = sha1(public_key_decoded).digest()
    digest_sha256 = sha256(public_key_decoded).digest()

    if ssh_keygen_format:
        fingerprint_sha1 = base64.b64encode(digest_sha1).rstrip(b"=").decode()
        fingerprint_sha256 = base64.b64encode(digest_sha256).rstrip(b"=").decode()
    else:
        fingerprint_sha1 = digest_sha1.hex()
        fingerprint_sha256 = digest_sha256.hex()

    return digest_md5.hex(), fingerprint_sha1, fingerprint_sha256
