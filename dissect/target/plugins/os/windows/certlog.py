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
    "filesystem/windows/certlog/attributes",
    [
        ("string", "table_name"),
        ("varint", "request_id"),
        ("string", "attribute_name"),
        ("string", "common_name"),
        ("path", "source"),
    ],
)

RequestsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/request",
    [
        ("string", "caller_name"),
        ("string", "common_name"),
        ("string", "country"),
        ("string", "device_serial_number"),
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
        ("string", "request_attributes"),
        ("string", "requester_name"),
        ("string", "signer_application_policies"),
        ("string", "signer_policies"),
        ("string", "state_or_province"),
        ("string", "street_address"),
        ("string", "sur_name"),
        ("string", "title"),
        ("string", "unstructured_address"),
        ("string", "unstructured_name"),
        ("string", "attestation_challenge"),
        ("string", "disposition"),
        ("string", "raw_archived_key"),
        ("string", "raw_name"),
        ("string", "raw_old_certificate"),
        ("string", "raw_precertificate"),
        ("string", "raw_request"),
        ("string", "request_flags"),
        ("varint", "request_id"),
        ("string", "request_type"),
        ("datetime", "resolved_when"),
        ("string", "revoked_effective_when"),
        ("string", "revoked_reason"),
        ("datetime", "revoked_when"),
        ("string", "status_code"),
        ("datetime", "submitted_when"),
        ("string", "table_name"),
        ("path", "source"),
    ],
)

CRLsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/crls",
    [
        ('string', 'crl_publish_error'),
        ('varint', 'count'),
        ('datetime', 'crl_last_published'),
        ('varint', 'crl_publish_attempts'),
        ('varint', 'crl_publish_flags'),
        ('varint', 'crl_publish_status_code'),
        ('datetime', 'effective'),
        ('string', 'min_base'),
        ('varint', 'name_id'),
        ('datetime', 'next_publish'),
        ('datetime', 'next_update'),
        ('varint', 'number'),
        ('datetime', 'propagation_complete'),
        ('string', 'raw_crl'),
        ('varint', 'row_id'),
        ('string', 'table_name'),
        ('string', 'this_publish'),
        ('datetime', 'this_update'),
        ("path", "source"),
    ],
)

CertLogRecord = Union[  # noqa: UP007
    RequestsRecord, RequestAttributesRecord
]

TRANSFORMS = {}
# {i: "".join("_" + c.lower() if c.isupper() else c for c in i.replace('$', ''))[1:] for i in a}
FIELD_MAPPINGS = {
    "$AttributeName": "attribute_name",
    "$AttributeValue": "common_name",
    "$CRLPublishError": "crl_publish_error",
    "$CallerName": "caller_name",
    "$CommonName": "common_name",
    "$Country": "country",
    "$DeviceSerialNumber": "device_serial_number",
    "$DispositionMessage": "disposition_message",
    "$DistinguishedName": "distinguished_name",
    "$DomainComponent": "domain_component",
    "$EMail": "email",
    "$EndorsementCertificateHash": "endorsement_certificate_hash",
    "$EndorsementKeyHash": "endorsement_key_hash",
    "$GivenName": "given_name",
    "$Initials": "initials",
    "$KeyRecoveryHashes": "key_recovery_hashes",
    "$Locality": "locality",
    "$Organization": "organization",
    "$OrganizationalUnit": "organizational_unit",
    "$RequestAttributes": "request_attributes",
    "$RequesterName": "requester_name",
    "$SignerApplicationPolicies": "signer_application_policies",
    "$SignerPolicies": "signer_policies",
    "$StateOrProvince": "state_or_province",
    "$StreetAddress": "street_address",
    "$SurName": "sur_name",
    "$Title": "title",
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
    "MinBase": "min_base",
    "NameId": "name_id",
    "NextPublish": "next_publish",
    "NextUpdate": "next_update",
    "Number": "number",
    "PropgationComplete": "propagation_complete",
    "RawArchivedKey": "raw_archived_key",
    "RawCRL": "raw_crl",
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
        - https://docs.microsoft.com/en-us/sql/relational-databases/performance-monitor/monitor-resource-usage-system-monitor?view=sql-server-ver15
        - https://blog.1234n6.com/2019/01/
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

    @export(record=RequestsRecord)
    def crls(self) -> Iterator[CRLsRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("CRLs", CRLsRecord)


#
# @export(record=RequestsRecord)
# def certificates(self) -> Iterator[RequestsRecord]:
#    """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.
#
#    Gives insight into the network usage of the system.
#    """
#    yield from self.read_records("Certificates", RequestsRecord)
#
# @export(record=RequestsRecord)
# def certificate_extension(self) -> Iterator[RequestsRecord]:
#    """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.
#
#    Gives insight into the network usage of the system.
#    """
#    yield from self.read_records("CertificateExtensions", RequestsRecord)
