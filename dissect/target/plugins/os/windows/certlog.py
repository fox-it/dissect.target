from __future__ import annotations

from typing import TYPE_CHECKING, Any, Union

from dissect.database.ese.tools import certlog
from dissect.database.exception import Error

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from dissect.target.target import Target

RequestAttributeRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/request_attribute",
    [
        ("string", "attribute_name"),
        ("string", "common_name"),
        ("varint", "request_id"),
        ("string", "table_name"),
        ("string", "ca"),
        ("path", "source"),
    ],
)

CertificateExtensionRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificate_extension",
    [
        ("varint", "extension_flags"),
        ("string", "extension_name"),
        ("bytes", "extension_raw_value"),
        ("varint", "request_id"),
        ("string", "table_name"),
        ("string", "ca"),
        ("path", "source"),
    ],
)

CertificateRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificate",
    [
        ("digest", "fingerprint"),
        ("string", "certificate_template"),
        ("string", "common_name"),
        ("string", "country"),
        ("string", "device_serial_number"),
        ("string", "subject_dn"),
        ("string", "domain_component"),
        ("string", "email"),
        ("string", "given_name"),
        ("string", "initials"),
        ("string", "locality"),
        ("string", "organization"),
        ("string", "organizational_unit"),
        ("string", "public_key_algorithm"),
        ("string", "serial_number_hex"),
        ("varint", "serial_number"),
        ("string", "state_or_province"),
        ("string", "street_address"),
        ("string", "subject_key_identifier"),
        ("string", "sur_name"),
        ("string", "title"),
        ("string", "unstructured_address"),
        ("string", "unstructured_name"),
        ("string", "upn"),
        ("string", "enrollment_flags"),
        ("string", "general_flags"),
        ("string", "issuer_name_id"),
        ("datetime", "not_valid_after"),
        ("datetime", "not_valid_before"),
        ("string", "private_key_flags"),
        ("string", "public_key"),
        ("varint", "public_key_length"),
        ("string", "public_key_params"),
        ("string", "publish_expired_cert_in_crl"),
        ("bytes", "raw_certificate"),
        ("bytes", "raw_name"),
        ("varint", "request_id"),
        ("string", "table_name"),
        ("string", "ca"),
        ("path", "source"),
    ],
)

RequestRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/request",
    [
        ("string", "attestation_challenge"),
        ("string", "caller_name"),
        ("string", "common_name"),
        ("string", "country"),
        ("string", "device_serial_number"),
        ("string", "disposition"),
        ("string", "disposition_message"),
        ("string", "subject_dn"),
        ("string", "domain_component"),
        ("string", "email"),
        ("string", "endorsement_certificate_hash"),
        ("string", "endorsement_key_hash"),
        ("string", "given_name"),
        ("string", "initials"),
        ("string", "key_recovery_hashes"),
        ("string", "locality"),
        ("string", "organization"),
        ("string", "organizational_unit"),
        ("string", "raw_archived_key"),
        ("bytes", "raw_name"),
        ("bytes", "raw_old_certificate"),
        ("bytes", "raw_precertificate"),
        ("bytes", "raw_request"),
        ("string", "request_attributes"),
        ("string", "requester_name"),
        ("string", "request_flags"),
        ("varint", "request_id"),
        ("string", "request_type"),
        ("datetime", "resolved_when"),
        ("string", "revoked_effective_when"),
        ("string", "revoked_reason"),
        ("datetime", "revoked_when"),
        ("string", "signer_application_policies"),
        ("string", "signer_policies"),
        ("string", "state_or_province"),
        ("string", "request_status_code"),
        ("string", "street_address"),
        ("datetime", "submitted_when"),
        ("string", "sur_name"),
        ("string", "title"),
        ("string", "unstructured_address"),
        ("string", "unstructured_name"),
        ("string", "table_name"),
        ("string", "ca"),
        ("path", "source"),
    ],
)

CRLRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/crl",
    [
        ("varint", "count"),
        ("datetime", "crl_last_published"),
        ("varint", "crl_publish_attempts"),
        ("string", "crl_publish_error"),
        ("varint", "crl_publish_flags"),
        ("varint", "crl_publish_status_code"),
        ("datetime", "ts_effective"),
        ("string", "min_base"),
        ("varint", "name_id"),
        ("datetime", "next_publish"),
        ("datetime", "next_update"),
        ("varint", "number"),
        ("datetime", "propagation_complete"),
        ("bytes", "raw_crl"),
        ("varint", "row_id"),
        ("datetime", "this_publish"),
        ("datetime", "this_update"),
        ("string", "table_name"),
        ("string", "ca"),
        ("path", "source"),
    ],
)

CertLogRecord = Union[  # noqa: UP007
    RequestRecord, RequestAttributeRecord, CertificateRecord, CRLRecord, CertificateExtensionRecord
]

# {i: "".join("_" + c.lower() if c.isupper() else c for c in i.replace('$', ''))[1:] for i in a}
FIELD_MAPPINGS = {
    "$AttributeName": "attribute_name",
    "$AttributeValue": "common_name",
    "$CRLPublishError": "crl_publish_error",
    "$CallerName": "caller_name",
    "$CertificateHash": "fingerprint",
    "$CertificateHash2": "fingerprint",
    "$CertificateTemplate": "certificate_template",
    "$CommonName": "common_name",
    "$Country": "country",
    "$DeviceSerialNumber": "device_serial_number",
    "$DispositionMessage": "disposition_message",
    "$DistinguishedName": "subject_dn",
    "$DomainComponent": "domain_component",
    "$EMail": "email",
    "$EndorsementCertificateHash": "endorsement_certificate_hash",
    "$EndorsementKeyHash": "endorsement_key_hash",
    "$ExtensionName": "extension_name",
    "$GivenName": "given_name",
    "$Initials": "initials",
    "$KeyRecoveryHashes": "key_recovery_hashes",
    "$Locality": "locality",
    "$Organization": "organization",
    "$OrganizationalUnit": "organizational_unit",
    "$PublicKeyAlgorithm": "public_key_algorithm",
    "$RequestAttributes": "request_attributes",
    "$RequesterName": "requester_name",
    "$SerialNumber": "serial_number_hex",
    "$SignerApplicationPolicies": "signer_application_policies",
    "$SignerPolicies": "signer_policies",
    "$StateOrProvince": "state_or_province",
    "$StreetAddress": "street_address",
    "$SubjectKeyIdentifier": "subject_key_identifier",
    "$SurName": "sur_name",
    "$Title": "title",
    "$UPN": "upn",
    "$UnstructuredAddress": "unstructured_address",
    "$UnstructuredName": "unstructured_name",
    "AttestationChallenge": "attestation_challenge",
    "CRLLastPublished": "crl_last_published",
    "CRLPublishAttempts": "crl_publish_attempts",
    "CRLPublishFlags": "crl_publish_flags",
    "CRLPublishStatusCode": "crl_publish_status_code",
    "Count": "count",
    "Disposition": "disposition",
    "Effective": "ts_effective",  # prevent record_field_inconsistency
    "EnrollmentFlags": "enrollment_flags",
    "ExtensionFlags": "extension_flags",
    "ExtensionRawValue": "extension_raw_value",
    "GeneralFlags": "general_flags",
    "IssuerNameID": "issuer_name_id",
    "MinBase": "min_base",
    "NameId": "name_id",
    "NextPublish": "next_publish",
    "NextUpdate": "next_update",
    "NotAfter": "not_valid_after",
    "NotBefore": "not_valid_before",
    "Number": "number",
    "PrivateKeyFlags": "private_key_flags",
    "PropagationComplete": "propagation_complete",
    "PropgationComplete": "propagation_complete",  # typo in some Windows versions
    "PublicKey": "public_key",
    "PublicKeyLength": "public_key_length",
    "PublicKeyParams": "public_key_params",
    "PublishExpiredCertInCRL": "publish_expired_cert_in_crl",
    "RawArchivedKey": "raw_archived_key",
    "RawCRL": "raw_crl",
    "RawCertificate": "raw_certificate",
    "RawName": "raw_name",
    "RawOldCertificate": "raw_old_certificate",
    "RawPrecertificate": "raw_precertificate",
    "RawRequest": "raw_request",
    "RequestFlags": "request_flags",
    "RequestID": "request_id",
    "RequestType": "request_type",
    "ResolvedWhen": "resolved_when",
    "RevokedEffectiveWhen": "revoked_effective_when",
    "RevokedReason": "revoked_reason",
    "RevokedWhen": "revoked_when",
    "RowId": "row_id",
    "StatusCode": "request_status_code",  # prevent record_field_inconsistency
    "SubmittedWhen": "submitted_when",
    "TableName": "table_name",
    "ThisPublish": "this_publish",
    "ThisUpdate": "this_update",
}


def format_fingerprint(input_hash: str | None, target: Target) -> tuple[str | None, str | None, str | None]:
    if input_hash:
        input_hash = input_hash.replace(" ", "")
        # hash is expected to be a sha1, but as it not documented, we make this function more flexible if hash is
        # in another standard format (md5/sha256), especially in the future
        match len(input_hash):
            case 32:
                return input_hash, None, None
            case 40:
                return None, input_hash, None
            case 64:
                return None, None, input_hash
            case _:
                target.log.warning(
                    "Unexpected hash size found while processing certlog "
                    "$CertificateHash/$CertificateHash2 column: len %d, content %s",
                    len(input_hash),
                    input_hash,
                )
    return None, None, None


def format_serial_number(serial_number_as_hex: str | None) -> str | None:
    if not serial_number_as_hex:
        return None
    return serial_number_as_hex.replace(" ", "")


def serial_number_as_int(serial_number_as_hex: str | None) -> int | None:
    if not serial_number_as_hex:
        return None
    return int(serial_number_as_hex, 16)


FORMATING_FUNC: dict[str, Callable[[Any, Target], Any]] = {
    "fingerprint": format_fingerprint,
    "serial_number_hex": format_serial_number,
}


class CertLogPlugin(Plugin):
    """Return all available data stored in CertLog databases.

    Certificate Authority databases are databases related to the Active Directory Certificate Services (AD CS) feature.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/5f06c74c-1a29-4fdf-b8dd-ae3300d1b90d
        - https://assets.crowdstrike.com/is/content/crowdstrikeinc/investigating-active-directory-certificate-abusepdf
        - https://learn.microsoft.com/en-gb/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/move-certificate-server-database-log-files
    """

    __namespace__ = "certlog"

    def __init__(self, target: Target):
        super().__init__(target)
        self._certlog_dbs: list[tuple[certlog.CertLog, Path]] = []
        for path in self.get_paths():
            try:
                self._certlog_dbs.append((certlog.CertLog(path.open(mode="rb")), path))
            except Error as e:  # noqa: PERF203
                self.target.log.warning("Error opening Certlog database")
                self.target.log.debug("", exc_info=e)

    def _get_paths(self) -> Iterator[Path]:
        """Return all artifact files of interest to the plugin."""
        certlog_dir = self.target.resolve("%windir%/System32/CertLog")
        if certlog_dir.exists():
            yield from certlog_dir.glob("*.edb")

    def check_compatible(self) -> None:
        if not self._certlog_dbs:
            raise UnsupportedPluginError("No Certificate Authority Databases found")

    def read_records(self, table_name: str, record_type: CertLogRecord) -> Iterator[CertLogRecord]:
        for db, path in self._certlog_dbs:
            ca_name = path.stem
            table = next((table for table in db.tables() if table.name == table_name), None)
            if not table:
                self.target.log.warning("Table not found for ca %s: %s", ca_name, table_name)
                continue
            columns = [c.name for c in table.columns]
            for entry in db.records(table_name=table_name):
                values = (entry[name] for name in columns)
                column_values = zip(columns, values, strict=False)

                record_values = {}
                for column, value in column_values:
                    new_column = FIELD_MAPPINGS.get(column)
                    if new_column in FORMATING_FUNC:
                        value = FORMATING_FUNC[new_column](value, self.target)
                    if new_column and new_column not in record_values:
                        record_values[new_column] = value
                        # Serial number is format as int and string, to ease search of a specific sn in both format
                        if new_column == "serial_number_hex":
                            record_values["serial_number"] = serial_number_as_int(value)
                    elif new_column:
                        self.target.log.debug(
                            "Unexpected element while processing %s entries : %s column already exists "
                            "(mapped from original column name %s). This may be cause by two column that were not"
                            " expected to be present in the same time.",
                            table_name,
                            new_column,
                            column,
                        )
                    else:
                        self.target.log.debug(
                            "Unexpected column for table %s in CA %s: %s", table_name, ca_name, column
                        )

                yield record_type(
                    _target=self.target,
                    source=path,
                    table_name=table_name,
                    ca=ca_name,
                    **record_values,
                )

    @export(record=RequestRecord)
    def requests(self) -> Iterator[RequestRecord]:
        """Return the contents of the ``Requests`` table from all Certificate Authority databases.

        Gives insight into certificates requested (caller name, request ID, request attributes).
        """
        yield from self.read_records("Requests", RequestRecord)

    @export(record=RequestAttributeRecord)
    def request_attributes(self) -> Iterator[RequestAttributeRecord]:
        """Return the contents of the ``RequestAttributes`` table from all Certificate Authority databases.

        Gives insight into attributes of requested certificates (same information as in ``request_attributes`` field
        of ``Requests`` table).
        """
        yield from self.read_records("RequestAttributes", RequestAttributeRecord)

    @export(record=CRLRecord)
    def crls(self) -> Iterator[CRLRecord]:
        """Return the contents of the ``CRLs`` table from all Certificate Authority databases.

        Gives insight into the Certificate Revocation List of a Certificate Authority.
        """
        yield from self.read_records("CRLs", CRLRecord)

    @export(record=CertificateRecord)
    def certificates(self) -> Iterator[CertificateRecord]:
        """Return the contents of ``Certificates`` table from all Certificate Authority databases.

        Gives insight into issued certificates for a Certificate authority (public key, validity date).
        """
        yield from self.read_records("Certificates", CertificateRecord)

    @export(record=CertificateExtensionRecord)
    def certificate_extensions(self) -> Iterator[CertificateExtensionRecord]:
        """Return the contents of ``CertificateExtensions`` table from all Certificate Authority databases.

        Gives insight into certificate extensions for a CA.
        """
        yield from self.read_records("CertificateExtensions", CertificateExtensionRecord)
