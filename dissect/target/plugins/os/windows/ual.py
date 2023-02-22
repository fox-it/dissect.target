from dissect.esedb.exceptions import Error
from dissect.esedb.tools import ual

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

ClientAccessRecord = TargetRecordDescriptor(
    "filesystem/windows/ual/client_access",
    [
        ("datetime", "last_access_date"),
        ("datetime", "access_date"),
        ("datetime", "insert_date"),
        ("net.ipaddress", "address"),
        ("string", "authenticated_user"),
        ("string", "client_name"),
        ("varint", "access_count"),
        ("varint", "total_access_count"),
        ("string", "tenant_id"),
        ("string", "role_guid"),
        ("string", "role_name"),
        ("string", "product_name"),
        ("string", "path"),
    ],
)

RoleAccessRecord = TargetRecordDescriptor(
    "filesystem/windows/ual/role_access",
    [
        ("datetime", "first_seen_date"),
        ("datetime", "last_seen_date"),
        ("string", "role_guid"),
        ("string", "role_name"),
        ("string", "product_name"),
        ("string", "path"),
    ],
)

VirtualMachineRecord = TargetRecordDescriptor(
    "filesystem/windows/ual/virtual_machines",
    [
        ("datetime", "creation_time"),
        ("datetime", "last_seen_active_date"),
        ("string", "vm_guid"),
        ("string", "bios_guid"),
        ("string", "serial_number"),
        ("string", "path"),
    ],
)

DomainSeenRecord = TargetRecordDescriptor(
    "filesystem/windows/ual/virtual_machines",
    [
        ("datetime", "last_seen_date"),
        ("net.ipaddress", "address"),
        ("string", "resolved_hostname"),
        ("string", "path"),
    ],
)

SystemIdentityRecord = TargetRecordDescriptor(
    "filesystem/windows/ual/system_identity",
    [
        ("datetime", "creation_time"),
        ("varint", "physical_processor_count"),
        ("varint", "cores_per_physical_processor"),
        ("varint", "logical_processors_per_physical_processor"),
        ("varint", "maximum_memory"),
        ("varint", "os_major_version"),
        ("varint", "os_minor_version"),
        ("varint", "os_build"),
        ("varint", "os_platform_id"),
        ("varint", "service_pack_major_version"),
        ("varint", "service_pack_minor_version"),
        ("varint", "os_suite_mask"),
        ("varint", "os_product_type"),
        ("varint", "os_current_time_zone"),
        ("varint", "os_daylight_in_effect"),
        ("string", "system_manufacturer"),
        ("string", "system_product_name"),
        ("string", "system_sm_bios_uuid"),
        ("string", "system_serial_number"),
        ("string", "system_dns_hostname"),
        ("string", "system_domain_name"),
        ("string", "os_serial_number"),
        ("string", "os_country_code"),
        ("string", "os_last_boot_up_time"),
        ("string", "path"),
    ],
)

FIELD_NAME_MAP = {
    "Address": "address",
    "AuthenticatedUserName": "authenticated_user",
    "BIOSGuid": "bios_guid",
    "ClientName": "client_name",
    "CoresPerPhysicalProcessor": "cores_per_physical_processor",
    "CreationTime": "creation_time",
    "FirstSeen": "first_seen_date",
    "HostName": "resolved_hostname",
    "InsertDate": "insert_date",
    "LastAccess": "last_access_date",
    "LastSeen": "last_seen_date",
    "LastSeenActive": "last_seen_active_date",
    "LogicalProcessorsPerPhysicalProcessor": "logical_processors_per_physical_processor",
    "MaximumMemory": "maximum_memory",
    "OSBuildNumber": "os_build",
    "OSCountryCode": "os_country_code",
    "OSCurrentTimeZone": "os_current_time_zone",
    "OSDaylightInEffect": "os_daylight_in_effect",
    "OSLastBootUpTime": "os_last_boot_up_time",
    "OSMajor": "os_major_version",
    "OSMinor": "os_minor_version",
    "OSPlatformId": "os_platform_id",
    "OSProductType": "os_product_type",
    "OSSerialNumber": "os_serial_number",
    "OSSuiteMask": "os_suite_mask",
    "PhysicalProcessorCount": "physical_processor_count",
    "ProductName": "product_name",
    "RoleGuid": "role_guid",
    "RoleName": "role_name",
    "SerialNumber": "serial_number",
    "ServicePackMajor": "service_pack_major_version",
    "ServicePackMinor": "service_pack_minor_version",
    "SystemDNSHostName": "system_dns_hostname",
    "SystemDomainName": "system_domain_name",
    "SystemManufacturer": "system_manufacturer",
    "SystemProductName": "system_product_name",
    "SystemSMBIOSUUID": "system_sm_bios_uuid",
    "SystemSerialNumber": "system_serial_number",
    "TenantId": "tenant_id",
    "TotalAccesses": "total_access_count",
    "VmGuid": "vm_guid",
}


class UalPlugin(Plugin):
    """Return all available User Access Log information.

    User Access Logging (UAL) is a logging system that aggregates client usage data by role and products on a local
    server. It helps Windows server administrators to quantify requests from client computers for roles and services on
    a local server.

    Sources:
        - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh849634(v=ws.11)
    """  # noqa: E501

    __namespace__ = "ual"

    LOG_DB_GLOB = "sysvol/Windows/System32/LogFiles/Sum/*.mdb"

    IDENTITY_DB_FILENAME = "SystemIdentity.mdb"
    IDENTITY_DB_PATH = f"sysvol/Windows/System32/LogFiles/Sum/{IDENTITY_DB_FILENAME}"

    def __init__(self, target):
        super().__init__(target)

        self.mdb_paths = self.find_mdb_files()

        self.role_guid_map = {}
        self.identity_db_parser = None
        self.populate_role_guid_map()

    def check_compatible(self):
        if not any([path.exists() for path in self.mdb_paths]):
            raise UnsupportedPluginError("No MDB files found")

    def find_mdb_files(self):
        return [
            path
            for path in self.target.fs.path("/").glob(self.LOG_DB_GLOB)
            if path.exists() and path.name != self.IDENTITY_DB_FILENAME
        ]

    def populate_role_guid_map(self):
        identity_db = self.target.fs.path(self.IDENTITY_DB_PATH)
        if not identity_db.exists():
            return

        fh = identity_db.open()
        try:
            self.identity_db_parser = ual.UAL(fh)
        except Error as e:
            self.target.log.warning("Error opening UAL SystemIdentity.mdb database", exc_info=e)
            return

        self.target.log.debug("SystemIdentity.mdb DB loaded")

        for record in self.identity_db_parser.get_table_records("ROLE_IDS"):
            self.role_guid_map[record.get("RoleGuid")] = {
                "product_name": record.get("ProductName"),
                "role_name": record.get("RoleName"),
            }

    def read_table_records(self, table_name):
        for mdb_path in self.mdb_paths:
            fh = mdb_path.open()
            try:
                parser = ual.UAL(fh)
            except Error as e:
                self.target.log.warning(f"Error opening {mdb_path} database", exc_info=e)
                continue

            for table_record in parser.get_table_records(table_name):
                values = {FIELD_NAME_MAP.get(key, key): value for key, value in table_record.items()}
                yield mdb_path, values

    @export(record=ClientAccessRecord)
    def client_access(self):
        """Return client access data within the User Access Logs."""
        for path, client_record in self.read_table_records("CLIENTS"):
            common_values = {k: v for k, v in client_record.items() if k != "activity_counts"}
            role_guid_data = self.role_guid_map.get(common_values.get("role_guid"), {})

            for access_date, access_count in client_record.get("activity_counts", []):
                yield ClientAccessRecord(
                    role_name=role_guid_data.get("role_name"),
                    product_name=role_guid_data.get("product_name"),
                    access_date=access_date,
                    access_count=access_count,
                    path=path,
                    _target=self.target,
                    **common_values,
                )

    @export(record=RoleAccessRecord)
    def role_access(self):
        """Return role access data within the User Access Logs."""
        for path, record in self.read_table_records("ROLE_ACCESS"):
            role_guid_data = self.role_guid_map.get(record.get("role_guid"), {})
            yield RoleAccessRecord(
                role_name=role_guid_data.get("role_name"),
                product_name=role_guid_data.get("product_name"),
                path=path,
                _target=self.target,
                **record,
            )

    @export(record=VirtualMachineRecord)
    def virtual_machines(self):
        """Return virtual machine data within the User Access Logs."""
        for path, record in self.read_table_records("VIRTUALMACHINES"):
            yield VirtualMachineRecord(path=path, _target=self.target, **record)

    @export(record=DomainSeenRecord)
    def domains_seen(self):
        """Return DNS data within the User Access Logs."""
        for path, record in self.read_table_records("DNS"):
            yield DomainSeenRecord(path=path, _target=self.target, **record)

    @export(record=SystemIdentityRecord)
    def system_identities(self):
        """Return system identity data within the User Access Logs."""
        if not self.identity_db_parser:
            return
        for record in self.identity_db_parser.get_table_records("SYSTEM_IDENTITY"):
            values = {FIELD_NAME_MAP.get(key, key): value for key, value in record.items()}
            yield SystemIdentityRecord(
                path=self.target.fs.path(self.IDENTITY_DB_PATH),
                _target=self.target,
                **values,
            )
