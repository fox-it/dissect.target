from __future__ import annotations

import base64
import binascii
from hashlib import md5, sha1, sha256

from dissect.cstruct import cstruct

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

rfc4716_def = """
struct ssh_string {
    uint32 length;
    char value[length];
}

struct ssh_private_key {
    char magic[15];

    ssh_string cipher;
    ssh_string kdf_name;
    ssh_string kdf_options;

    uint32 number_of_keys;

    ssh_string public;
    ssh_string private;
}
"""

c_rfc4716 = cstruct(endian=">").load(rfc4716_def)

RFC4716_MARKER_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"
RFC4716_MARKER_END = b"-----END OPENSSH PRIVATE KEY-----"
RFC4716_MAGIC = b"openssh-key-v1\x00"
RFC4716_PADDING = b"\x01\x02\x03\x04\x05\x06\x07"
RFC4716_NONE = b"none"

PKCS8_MARKER_START = b"-----BEGIN PRIVATE KEY-----"
PKCS8_MARKER_END = b"-----END PRIVATE KEY-----"
PKCS8_MARKER_START_ENCRYPTED = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
PKCS8_MARKER_END_ENCRYPTED = b"-----END ENCRYPTED PRIVATE KEY-----"

PEM_MARKER_START_RSA = b"-----BEGIN RSA PRIVATE KEY-----"
PEM_MARKER_END_RSA = b"-----END RSA PRIVATE KEY-----"
PEM_MARKER_START_DSA = b"-----BEGIN DSA PRIVATE KEY-----"
PEM_MARKER_END_DSA = b"-----END DSA PRIVATE KEY-----"
PEM_MARKER_START_EC = b"-----BEGIN EC PRIVATE KEY-----"
PEM_MARKER_END_EC = b"-----END EC PRIVATE KEY-----"
PEM_ENCRYPTED = b"ENCRYPTED"


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
        raise TypeError("Provided public key should be bytes")

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


def is_rfc4716(data: bytes) -> bool:
    """Validate data is a valid looking SSH private key in the OpenSSH format."""
    return data.startswith(RFC4716_MARKER_START) and data.endswith(RFC4716_MARKER_END)


def decode_rfc4716(data: bytes) -> bytes:
    """Base64 decode the private key data."""
    encoded_key_data = data.removeprefix(RFC4716_MARKER_START).removesuffix(RFC4716_MARKER_END)
    try:
        return base64.b64decode(encoded_key_data)
    except binascii.Error:
        raise ValueError("Error decoding RFC4716 key data")


def is_pkcs8(data: bytes) -> bool:
    """Validate data is a valid looking PKCS8 SSH private key."""
    return (data.startswith(PKCS8_MARKER_START) and data.endswith(PKCS8_MARKER_END)) or (
        data.startswith(PKCS8_MARKER_START_ENCRYPTED) and data.endswith(PKCS8_MARKER_END_ENCRYPTED)
    )


def is_pem(data: bytes) -> bool:
    """Validate data is a valid looking PEM SSH private key."""
    return (
        (data.startswith(PEM_MARKER_START_RSA) and data.endswith(PEM_MARKER_END_RSA))
        or (data.startswith(PEM_MARKER_START_DSA) and data.endswith(PEM_MARKER_END_DSA))
        or (data.startswith(PEM_MARKER_START_EC) and data.endswith(PEM_MARKER_END_EC))
    )


class SSHPrivateKey:
    """A class to parse (OpenSSH-supported) SSH private keys.

    OpenSSH supports three types of keys:
    * RFC4716 (default)
    * PKCS8
    * PEM
    """

    def __init__(self, data: bytes):
        self.key_type = None
        self.public_key = None
        self.comment = ""

        if is_rfc4716(data):
            self.format = "RFC4716"
            self._parse_rfc4716(data)

        elif is_pkcs8(data):
            self.format = "PKCS8"
            self.is_encrypted = data.startswith(PKCS8_MARKER_START_ENCRYPTED)

        elif is_pem(data):
            self.format = "PEM"
            self._parse_pem(data)

        else:
            raise ValueError("Unsupported private key format")

    def _parse_rfc4716(self, data: bytes) -> None:
        """Parse OpenSSH format SSH private keys.

        The format:
        "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
        32-bit length, "none"   # ciphername length and string
        32-bit length, "none"   # kdfname length and string
        32-bit length, nil      # kdf (0 length, no kdf)
        32-bit 0x01             # number of keys, hard-coded to 1 (no length)
        32-bit length, sshpub   # public key in ssh format
            32-bit length, keytype
            32-bit length, pub0
            32-bit length, pub1
        32-bit length for rnd+prv+comment+pad
            64-bit dummy checksum?  # a random 32-bit int, repeated
            32-bit length, keytype  # the private key (including public)
            32-bit length, pub0     # Public Key parts
            32-bit length, pub1
            32-bit length, prv0     # Private Key parts
            ...                     # (number varies by type)
            32-bit length, comment  # comment string
            padding bytes 0x010203  # pad to blocksize (see notes below)

        Source: https://coolaj86.com/articles/the-openssh-private-key-format/
        """

        key_data = decode_rfc4716(data)
        private_key = c_rfc4716.ssh_private_key(key_data)

        # RFC4716 only supports 1 key at the moment.
        if private_key.magic != RFC4716_MAGIC or private_key.number_of_keys != 1:
            raise ValueError("Unexpected number of keys for RFC4716 format private key")

        self.is_encrypted = private_key.cipher.value != RFC4716_NONE

        self.public_key = base64.b64encode(private_key.public.value)
        public_key_type = c_rfc4716.ssh_string(private_key.public.value)
        self.key_type = public_key_type.value

        if not self.is_encrypted:
            private_key_data = private_key.private.value.rstrip(RFC4716_PADDING)

            # We skip the two dummy uint32s at the start.
            private_key_index = 8

            private_key_type = c_rfc4716.ssh_string(private_key_data[private_key_index:])
            private_key_index += 4 + private_key_type.length
            self.key_type = private_key_type.value

            private_key_fields = []
            while private_key_index < len(private_key_data):
                field = c_rfc4716.ssh_string(private_key_data[private_key_index:])
                private_key_index += 4 + field.length
                private_key_fields.append(field)

            # There is always a comment present (with a length field of 0 for empty comments).
            self.comment = private_key_fields[-1].value

    def _parse_pem(self, data: bytes) -> None:
        """Detect key type and encryption of PEM keys."""
        self.is_encrypted = PEM_ENCRYPTED in data

        if data.startswith(PEM_MARKER_START_RSA):
            self.key_type = "ssh-rsa"

        elif data.startswith(PEM_MARKER_START_DSA):
            self.key_type = "ssh-dss"

        # This is not a valid SSH key type, but we currently do not detect the specific ecdsa variant.
        else:
            self.key_type = "ecdsa"
