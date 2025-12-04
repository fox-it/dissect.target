from __future__ import annotations

from typing import TYPE_CHECKING, Union

from dissect.database.ese.tools import certlog
from dissect.database.exception import Error

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

log = get_logger(__name__)

RequestAttributesRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/request_attributes",
    [
        ("path", "source"),
        ("string", "attribute_name"),
        ("string", "common_name"),
        ("string", "table_name"),
        ("varint", "request_id"),
    ],
)

CertificateExtensionsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificate_extensions",
    [
        ("path", "source"),
        ("string", "extension_raw_value"),
        ("varint", "extension_flags"),
        ("string", "extension_name"),
        ("string", "table_name"),
        ("varint", "request_id"),
    ],
)

CertificatesRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificates",
    [
        ("string", "certificate_hash2"),
        ("string", "certificate_template"),
        ("string", "common_name"),
        ("string", "country"),
        ("string", "device_serial_number"),
        ("string", "distinguished_name"),
        ("string", "domain_component"),
        ("string", "email"),
        ("string", "given_name"),
        ("string", "initials"),
        ("string", "locality"),
        ("string", "organization"),
        ("string", "organizational_unit"),
        ("string", "public_key_algorithm"),
        ("string", "serial_number"),
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
        ("datetime", "not_after"),
        ("datetime", "not_before"),
        ("string", "private_key_flags"),
        ("string", "public_key"),
        ("varint", "public_key_length"),
        ("string", "public_key_params"),
        ("string", "publish_expired_cert_in_crl"),
        ("string", "raw_certificate"),
        ("string", "raw_name"),
        ("varint", "request_id"),
        ("string", "table_name"),
        ("path", "source"),
    ],
)

RequestsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/request",
    [
        ("datetime", "resolved_when"),
        ("datetime", "revoked_when"),
        ("datetime", "submitted_when"),
        ("path", "source"),
        ("string", "attestation_challenge"),
        ("string", "caller_name"),
        ("string", "common_name"),
        ("string", "country"),
        ("string", "device_serial_number"),
        ("string", "disposition"),
        ("string", "disposition_message"),
        ("string", "distinguished_name"),
        ("string", "domain_component"),
        ("string", "e_mail"),
        ("string", "endorsement_certificate_hash"),
        ("string", "endorsement_key_hash"),
        ("string", "given_name"),
        ("string", "initials"),
        ("string", "key_recovery_hashes"),
        ("string", "locality"),
        ("string", "organization"),
        ("string", "organizational_unit"),
        ("string", "raw_archived_key"),
        ("string", "raw_name"),
        ("string", "raw_old_certificate"),
        ("string", "raw_precertificate"),
        ("string", "raw_request"),
        ("string", "request_attributes"),
        ("string", "request_flags"),
        ("string", "request_type"),
        ("string", "requester_name"),
        ("string", "revoked_effective_when"),
        ("string", "revoked_reason"),
        ("string", "signer_application_policies"),
        ("string", "signer_policies"),
        ("string", "state_or_province"),
        ("string", "status_code"),
        ("string", "street_address"),
        ("string", "sur_name"),
        ("string", "table_name"),
        ("string", "title"),
        ("string", "unstructured_address"),
        ("string", "unstructured_name"),
        ("varint", "request_id"),
    ],
)

CRLsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/crls",
    [
        ("datetime", "crl_last_published"),
        ("datetime", "effective"),
        ("datetime", "next_publish"),
        ("datetime", "next_update"),
        ("datetime", "propagation_complete"),
        ("datetime", "this_update"),
        ("path", "source"),
        ("string", "crl_publish_error"),
        ("string", "min_base"),
        ("string", "raw_crl"),
        ("string", "table_name"),
        ("string", "this_publish"),
        ("varint", "count"),
        ("varint", "crl_publish_attempts"),
        ("varint", "crl_publish_flags"),
        ("varint", "crl_publish_status_code"),
        ("varint", "name_id"),
        ("varint", "number"),
        ("varint", "row_id"),
    ],
)

CertLogRecord = Union[  # noqa: UP007
    RequestsRecord, RequestAttributesRecord, CertificatesRecord, CRLsRecord, CertificateExtensionsRecord
]

TRANSFORMS = {}
# {i: "".join("_" + c.lower() if c.isupper() else c for c in i.replace('$', ''))[1:] for i in a}
FIELD_MAPPINGS = {
    "$AttributeName": "attribute_name",
    "$AttributeValue": "common_name",
    "$CRLPublishError": "crl_publish_error",
    "$CallerName": "caller_name",
    "$CertificateHash2": "certificate_hash2",
    "$CertificateTemplate": "certificate_template",
    "$CommonName": "common_name",
    "$Country": "country",
    "$DeviceSerialNumber": "device_serial_number",
    "$DispositionMessage": "disposition_message",
    "$DistinguishedName": "distinguished_name",
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
    "$SerialNumber": "serial_number",
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
    "Effective": "effective",
    "EnrollmentFlags": "enrollment_flags",
    "ExtensionFlags": "extension_flags",
    "ExtensionRawValue": "extension_raw_value",
    "GeneralFlags": "general_flags",
    "IssuerNameID": "issuer_name_id",
    "MinBase": "min_base",
    "NameId": "name_id",
    "NextPublish": "next_publish",
    "NextUpdate": "next_update",
    "NotAfter": "not_after",
    "NotBefore": "not_before",
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
    "StatusCode": "status_code",
    "SubmittedWhen": "submitted_when",
    "TableName": "table_name",
    "ThisPublish": "this_publish",
    "ThisUpdate": "this_update",
}


class CertLogPlugin(Plugin):
    """Return all available SRUM data stored in the SRUDB.dat.

    The System Resource Usage Monitor (SRUM) stores its information in a SRUDB.dat file. As the names suggests, it
    contains data about resource usage, such as network and memory usage by applications.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/5f06c74c-1a29-4fdf-b8dd-ae3300d1b90d
    """

    __namespace__ = "certlog"

    def __init__(self, target: Target):
        super().__init__(target)
        self._certlog_dbs: list[certlog.CertLog, Path] = []
        for path in self.get_paths():
            try:
                self._certlog_dbs.append((certlog.CertLog(path.open()), path))
            except Error as e:
                self.target.log.warning("Error opening Certlog database")
                self.target.log.debug("", exc_info=e)

    def _get_paths(self) -> Iterator[Path]:
        """Return all artifact files of interest to the plugin.

        To be implemented by the plugin subclass.
        """
        certlog_dir = self.target.resolve("%windir%/System32/CertLog")
        if certlog_dir.exists():
            yield from certlog_dir.glob("*.edb")

    def check_compatible(self) -> None:
        if not self._certlog_dbs:
            raise UnsupportedPluginError("No Certlog Databases found")

    def read_records(self, table_name: str, record_type: CertLogRecord) -> Iterator[CertLogRecord]:
        for db, path in self._certlog_dbs:
            table = [table for table in db.tables() if table.name == table_name]
            if not table:
                self.target.log.warning("Table not found: %s", table_name)
                return iter(())
            columns = [c.name for c in table[0].columns]
            for entry in db.records(table_name=table_name):
                values = (entry[name] for name in columns)
                column_values = zip(columns, values, strict=False)

                record_values = {}
                for column, value in column_values:
                    new_column = FIELD_MAPPINGS.get(column)
                    if new_column:
                        record_values[new_column] = value
                    else:
                        self.target.log.debug("Unexpected columns for table %s : %s", table_name, column)

                yield record_type(
                    _target=self.target,
                    source=path,
                    table_name=table_name,
                    **record_values,
                )

    @export(record=RequestsRecord)
    def requests(self) -> Iterator[RequestsRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("Requests", RequestsRecord)

    @export(record=RequestAttributesRecord)
    def request_attributes(self) -> Iterator[RequestAttributesRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("RequestAttributes", RequestAttributesRecord)

    @export(record=CRLsRecord)
    def crls(self) -> Iterator[CRLsRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("CRLs", CRLsRecord)

    @export(record=CertificatesRecord)
    def certificates(self) -> Iterator[CertificatesRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("Certificates", CertificatesRecord)

    @export(record=CertificateExtensionsRecord)
    def certificate_extension(self) -> Iterator[CertificateExtensionsRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("CertificateExtensions", CertificateExtensionsRecord)
