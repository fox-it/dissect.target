from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path

from flow.record import RecordDescriptor

try:
    from asn1crypto import pem, x509

    HAS_ASN1 = True

except ImportError:
    HAS_ASN1 = False

COMMON_CERTIFICATE_FIELDS = [
    ("digest", "fingerprint"),
    ("varint", "serial_number"),
    ("string", "serial_number_hex"),
    ("datetime", "not_valid_before"),
    ("datetime", "not_valid_after"),
    ("string", "issuer_dn"),
    ("string", "subject_dn"),
    ("bytes", "pem"),
]

CertificateRecord = RecordDescriptor(
    "certificate",
    [
        *COMMON_CERTIFICATE_FIELDS,
    ],
)

# Translation layer for asn1crypto names to RFC4514 names.
# References: https://github.com/wbond/asn1crypto/blob/master/asn1crypto/x509.py @ NameType
# References: https://github.com/pyca/cryptography/blob/main/src/cryptography/x509/name.py
NAMEOID_TO_NAME = {
    "common_name": "CN",  # 2.5.4.3
    "country_name": "C",  # 2.5.4.6
    "locality_name": "L",  # 2.5.4.7
    "state_or_province_name": "ST",  # 2.5.4.8
    "street_address": "STREET",  # 2.5.4.9
    "organization_name": "O",  # 2.5.4.10
    "organizational_unit_name": "OU",  # 2.5.4.11
    "domain_component": "DC",  # 0.9.2342.192.00300.100.1.25
    "user_id": "UID",  # 0.9.2342.192.00300.100.1.1
}


def compute_pem_fingerprints(pem: str | bytes) -> tuple[str, str, str]:
    """Compute the MD5, SHA-1 and SHA-256 fingerprint hash of a x509 certificate PEM."""

    if pem is None:
        raise ValueError("No PEM provided")

    if isinstance(pem, bytes):
        pem = pem.decode()

    elif not isinstance(pem, str):
        raise TypeError("Provided PEM is not str or bytes")

    stripped_pem = pem.strip().removeprefix("-----BEGIN CERTIFICATE-----").removesuffix("-----END CERTIFICATE-----")

    try:
        der = base64.b64decode(stripped_pem)
    except binascii.Error as e:
        raise ValueError(f"Unable to parse PEM: {e!s}") from e

    md5 = hashlib.md5(der).hexdigest()
    sha1 = hashlib.sha1(der).hexdigest()
    sha256 = hashlib.sha256(der).hexdigest()

    return md5, sha1, sha256


def format_serial_number_as_hex(serial_number: int | None) -> str | None:
    """Format serial_number from integer to hex.

    Add a prefix 0 if output length is not pair, in order to be consistent with usual serial_number representation
    (navigator, openssl etc...).
    For negative number use the same representation as navigator, which differ from OpenSSL.

    For example for -1337::

        OpenSSL : Serial Number: -1337 (-0x539)
        Navigator : FA C7

    Args:
        serial_number: The serial number to format as hex.
    """
    if serial_number is None:
        return serial_number

    if serial_number > 0:
        serial_number_as_hex = f"{serial_number:x}"
        if len(serial_number_as_hex) % 2 == 1:
            serial_number_as_hex = f"0{serial_number_as_hex}"
        return serial_number_as_hex
    # Representation is always a multiple of 8 bits, we need to compute this size
    output_bin_len = (8 - (serial_number.bit_length() % 8) + serial_number.bit_length())
    return f"{serial_number & ((1 << output_bin_len) - 1):x}"


def parse_x509(file: str | bytes | Path) -> CertificateRecord:
    """Parses a PEM file. Returns a CertificateREcord. Does not parse a public key embedded in a x509 certificate."""

    if isinstance(file, str):
        content = file.encode()

    elif isinstance(file, bytes):
        content = file

    elif isinstance(file, Path) or hasattr(file, "read_bytes"):
        content = file.read_bytes()

    else:
        raise TypeError("Parameter file is not of type str, bytes or Path")

    if not HAS_ASN1:
        raise ValueError("Missing asn1crypto dependency")

    md5, _, _ = compute_pem_fingerprints(content.decode())
    _, _, der = pem.unarmor(content)
    crt = x509.Certificate.load(der)

    issuer = []
    for key, value in crt.issuer.native.items():
        issuer.append(f"{NAMEOID_TO_NAME.get(key, key)}={value}")

    subject = []
    for key, value in crt.subject.native.items():
        subject.append(f"{NAMEOID_TO_NAME.get(key, key)}={value}")

    return CertificateRecord(
        not_valid_before=crt.not_valid_before,
        not_valid_after=crt.not_valid_after,
        issuer_dn=",".join(issuer),
        subject_dn=",".join(subject),
        fingerprint=(md5, crt.sha1.hex(), crt.sha256.hex()),
        serial_number=crt.serial_number,
        serial_number_hex=format_serial_number_as_hex(crt.serial_number),
        pem=crt.dump(),
    )
