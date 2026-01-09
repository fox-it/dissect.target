from __future__ import annotations

from binascii import hexlify
from datetime import datetime
from functools import cached_property
from hashlib import md5
from typing import TYPE_CHECKING, Any

from Crypto.Cipher import AES, ARC4, DES
from dissect.cstruct import cstruct
from dissect.database.ese.ntds import NTDS
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export
from dissect.target.plugins.os.windows.credential.sam import rid_to_key

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct.types import structure
    from dissect.database.ese.ntds.objects import Computer, User

    from dissect.target.target import Target


# Kerberos encryption type mappings
KERBEROS_TYPE = {
    # DES
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    # RC4
    23: "rc4-hmac",
    -133: "rc4-hmac-exp",
    0xFFFFFF74: "rc4_hmac_old",
    # AES (RFC 3962)
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    # AES (newer RFC 8009)
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    # Other / legacy
    16: "des3-cbc-sha1",
    24: "rc4-hmac-exp-old",
}

# SAM account type constants
SAM_ACCOUNT_TYPE_INTERNAL_TO_NAME = {
    0x0: "SAM_DOMAIN_OBJECT",
    0x10000000: "SAM_GROUP_OBJECT",
    0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
    0x20000000: "SAM_ALIAS_OBJECT",
    0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
    0x30000000: "SAM_USER_OBJECT",
    0x30000001: "SAM_MACHINE_ACCOUNT",
    0x30000002: "SAM_TRUST_ACCOUNT",
    0x40000000: "SAM_APP_BASIC_GROUP",
    0x40000001: "SAM_APP_QUERY_GROUP",
    0x7FFFFFFF: "SAM_ACCOUNT_TYPE_MAX",
}


GENERIC_FIELDS = [
    ("string", "common_name"),
    ("string", "upn"),
    ("string", "sam_name"),
    ("string", "sam_type"),
    ("string", "description"),
    ("string", "sid"),
    ("varint", "rid"),
    ("datetime", "password_last_set"),
    ("datetime", "logon_last_failed"),
    ("datetime", "logon_last_success"),
    ("datetime", "account_expires"),
    ("datetime", "creation_time"),
    ("datetime", "last_modified_time"),
    ("boolean", "admin_count"),
    ("boolean", "is_deleted"),
    ("string", "lm"),
    ("string[]", "lm_history"),
    ("string", "nt"),
    ("string[]", "nt_history"),
    ("string", "cleartext_password"),
    ("string", "credential_type"),
    ("string", "kerberos_type"),
    ("string", "kerberos_key"),
    ("string", "default_salt"),
    ("uint32", "iteration_count"),
    ("uint32", "default_iteration_count"),
    ("string[]", "packages"),
    ("string", "w_digest"),
    ("uint32", "user_account_control"),
    *[("boolean", flag.name.lower()) for flag in UserAccountControl],
    ("string[]", "object_classes"),
    ("string", "distinguished_name"),
    ("string", "object_guid"),
    ("uint32", "primary_group_id"),
    ("string[]", "member_of"),
    ("string[]", "service_principal_name"),
]

# Record descriptor for NTDS user secrets
NtdsUserAccountRecord = TargetRecordDescriptor(
    "windows/credential/ntds/user",
    [
        *GENERIC_FIELDS,
        ("string", "info"),
        ("string", "comment"),
        ("string", "telephone_number"),
        ("string", "home_directory"),
    ],
)
NtdsComputerAccountRecord = TargetRecordDescriptor(
    "windows/credential/ntds/computer",
    [
        *GENERIC_FIELDS,
        ("string", "dns_hostname"),
        ("string", "operating_system"),
        ("string", "operating_system_version"),
    ],
)

crypto_structures = """
typedef struct {
    BYTE Header[8];
    BYTE KeyMaterial[16];
    DWORD Unknown;
    BYTE EncryptedHash[EOF];
} CRYPTED_HASHW16;

typedef struct {
    BYTE Header[8];
    BYTE KeyMaterial[16];
    BYTE EncryptedHash[EOF];
} CRYPTED_HISTORY;

typedef struct {
    BYTE Header[8];
    BYTE KeyMaterial[16];
    BYTE EncryptedHash[EOF];
} CRYPTED_BLOB;

typedef struct {
    CHAR Header;
    CHAR Padding[3];
    CHAR Key[16];
} PEK_KEY;

typedef struct {
    BYTE Header[8];
    BYTE KeyMaterial[16];
    BYTE EncryptedHash[16];
} CRYPTED_HASH;
"""


# Initialize cstruct parsers
c_ntds_crypto = cstruct().load(crypto_structures)


class NtdsPlugin(Plugin):
    """Plugin to parse NTDS.dit Active Directory database and extract user credentials.

    This plugin decrypts and extracts user password hashes, password history,
    Kerberos keys, and other authentication data from the NTDS.dit database
    found on Windows Domain Controllers.
    """

    __namespace__ = "ntds"

    # Encryption and crypto constants
    class CryptoConstants:
        """Constants used for cryptographic operations."""

        DES_BLOCK_SIZE = 8
        IV_SIZE = 16
        NTLM_HASH_SIZE = 16

        # The header contains the PEK index encoded in the hex representation of the header bytes.
        PEK_INDEX_HEX_START = 8
        PEK_INDEX_HEX_END = 10

        # Version-specific headers
        WINDOWS_2016_TP4_HASH_HEADER = b"\x13\x00\x00\x00"

        # Default values
        DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
        DEFAULT_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
        EMPTY_BYTE = b"\x00"

    def __init__(self, target: Target):
        """Initialize the NTDS plugin.

        Args:
            target: The target system to analyze.
        """
        super().__init__(target)

        if self.target.has_function("registry"):
            ntds_path_key = self.target.registry.value(
                key="HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", value="DSA Database file"
            )
            self.ntds_path = self.target.fs.path(ntds_path_key.value)

    def check_compatible(self) -> None:
        """Check if the plugin can run on the target system.

        Raises:
            UnsupportedPluginError: If NTDS.dit is not found or system hive is missing.
        """
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Registry function not available")

        if not self.ntds_path.exists():
            raise UnsupportedPluginError("NTDS.dit file not found")

        if not self.target.has_function("lsa") or not hasattr(self.target.lsa, "syskey"):
            raise UnsupportedPluginError("System Hive is not present or LSA function not available")

    @cached_property
    def ntds(self) -> NTDS:
        return NTDS(self.ntds_path.open())

    @cached_property
    def pek_list(self) -> list[bytes]:
        """Extract PEK list structure and decrypt PEK keys.

        Raises:
            RuntimeError: If PEK list cannot be found in the database or couldn't extract PEK keys from the PEK list.

        Returns:
            pek_list: list containing PEK keys
        """
        self.ntds.pek.unlock(self.target.lsa.syskey)
        return self.ntds.pek.keys

    def _derive_rc4_key(self, key: bytes, key_material: bytes, iterations: int) -> bytes:
        """Derive RC4 key using MD5 with multiple iterations.

        Args:
            key: RC4 key.
            key_material: Random key material for this encryption.
            iterations: Number of MD5 iterations to perform.

        Returns:
            16-byte RC4 key.
        """
        hasher = md5()
        hasher.update(key)
        for _ in range(iterations):
            hasher.update(key_material)
        return hasher.digest()

    def _aes_decrypt(self, key: bytes, data: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-CBC.

        Args:
            key: AES encryption key.
            data: Encrypted data.
            iv: Initialization vector.

        Returns:
            Decrypted data.
        """
        aes = AES.new(key, AES.MODE_CBC, iv)
        plain = b""

        # Decrypt in IV-sized blocks
        for idx in range(0, len(data), self.CryptoConstants.IV_SIZE):
            block = data[idx : idx + self.CryptoConstants.IV_SIZE]

            # Pad incomplete blocks
            if len(block) < self.CryptoConstants.IV_SIZE:
                padding_size = self.CryptoConstants.IV_SIZE - len(block)
                block = block + (self.CryptoConstants.EMPTY_BYTE * padding_size)

            plain += aes.decrypt(block)

        return plain

    def _get_pek_index_from_header(self, header: bytes) -> int:
        """Extract PEK index from header bytes.

        The PEK index is encoded in the hex representation of the header
        at positions 8:10.

        Args:
            header: Header bytes containing encoded PEK index.

        Returns:
            PEK index value.
        """
        hex_header = hexlify(bytearray(header))
        start = self.CryptoConstants.PEK_INDEX_HEX_START
        end = self.CryptoConstants.PEK_INDEX_HEX_END
        return int(hex_header[start:end], 16)

    def _remove_rc4_layer(self, crypted: structure) -> bytes:
        """Remove RC4 encryption layer using PEK key.

        Args:
            crypted: Encrypted structure with Header, KeyMaterial, and EncryptedHash.

        Returns:
            Data with RC4 layer removed.
        """
        pek_index = self._get_pek_index_from_header(crypted.Header)
        rc4_key = self._derive_rc4_key(
            self.pek_list[pek_index],
            bytearray(crypted.KeyMaterial),
            iterations=1,  # Single iteration for hash decryption
        )

        rc4 = ARC4.new(rc4_key)
        return rc4.encrypt(bytearray(crypted.EncryptedHash))

    def _remove_des_layer(self, crypted_hash: bytes, rid: int) -> bytes:
        """Remove final DES encryption layer using RID-derived keys.

        The hash is split into two 8-byte blocks, each decrypted with
        a different RID-derived key.

        Args:
            crypted_hash: 16-byte DES-encrypted hash.
            rid: Relative ID of the user account.

        Returns:
            16-byte decrypted hash.

        Raises:
            ValueError: If crypted_hash is not 16 bytes.
        """
        expected_size = 2 * self.CryptoConstants.DES_BLOCK_SIZE
        if len(crypted_hash) != expected_size:
            raise ValueError(f"crypted_hash must be {expected_size} bytes long")

        key1, key2 = rid_to_key(rid)
        des1 = DES.new(key1, DES.MODE_ECB)
        des2 = DES.new(key2, DES.MODE_ECB)

        block_size = self.CryptoConstants.DES_BLOCK_SIZE
        block1 = des1.decrypt(crypted_hash[:block_size])
        block2 = des2.decrypt(crypted_hash[block_size : 2 * block_size])

        return block1 + block2

    def _decrypt_hash(self, blob: bytes | None, rid: int, is_lm: bool) -> str:
        """Decrypt a single NT or LM password hash.

        Args:
            blob: Encrypted hash blob from database.
            rid: User's relative ID.
            is_lm: True for LM hash, False for NT hash.

        Returns:
            Hex string of the decrypted hash.
        """
        if not blob:
            return self.CryptoConstants.DEFAULT_LM_HASH if is_lm else self.CryptoConstants.DEFAULT_NT_HASH

        crypted = c_ntds_crypto.CRYPTED_HASH(blob)
        header_bytes = bytearray(crypted.Header)

        if header_bytes.startswith(self.CryptoConstants.WINDOWS_2016_TP4_HASH_HEADER):
            # Modern encryption (AES)
            decrypted = self._decrypt_hash_modern(blob, rid)
        else:
            # Legacy encryption (RC4 + DES)
            decrypted = self._decrypt_hash_legacy(crypted, rid)

        return hexlify(decrypted).decode()

    def _decrypt_hash_modern(self, blob: bytes, rid: int) -> bytes:
        """Decrypt hash using modern AES encryption (Windows Server 2016+).

        Args:
            blob: Encrypted hash blob.
            rid: User's relative ID.

        Returns:
            Decrypted hash bytes.
        """
        # Parse structure with correct size
        crypted = c_ntds_crypto.CRYPTED_HASHW16(blob)

        # Decrypt AES layer
        pek_index = self._get_pek_index_from_header(crypted.Header)
        decrypted = self._aes_decrypt(
            self.pek_list[pek_index],
            bytearray(crypted.EncryptedHash[: self.CryptoConstants.NTLM_HASH_SIZE]),
            bytearray(crypted.KeyMaterial),
        )

        # Remove DES layer
        return self._remove_des_layer(decrypted, rid)

    def _decrypt_hash_legacy(self, crypted: structure, rid: int) -> bytes:
        """Decrypt hash using legacy RC4+DES encryption.

        Args:
            crypted: Encrypted hash structure.
            rid: User's relative ID.

        Returns:
            Decrypted hash bytes.
        """
        tmp = self._remove_rc4_layer(crypted)
        return self._remove_des_layer(tmp, rid)

    def _decrypt_history(self, blob: bytes, rid: int) -> list[str]:
        """Decrypt password history containing multiple hashes.

        Args:
            blob: Encrypted history blob.
            rid: User's relative ID.

        Returns:
            List of hex-encoded password hashes.
        """
        if not blob:
            return []

        # Parse structure
        crypted = c_ntds_crypto.CRYPTED_HISTORY(blob)
        header_bytes = bytearray(crypted.Header)

        if header_bytes.startswith(self.CryptoConstants.WINDOWS_2016_TP4_HASH_HEADER):
            # Modern AES encryption
            decrypted = self._decrypt_history_modern(blob)
        else:
            # Legacy RC4 encryption
            decrypted = self._remove_rc4_layer(crypted)

        # Split into individual hashes and remove DES layer from each
        hash_size = self.CryptoConstants.NTLM_HASH_SIZE
        hashes = []
        for i in range(0, len(decrypted), hash_size):
            block = decrypted[i : i + hash_size]
            if len(block) == hash_size:
                hash_bytes = self._remove_des_layer(block, rid)
                hashes.append(hexlify(hash_bytes).decode())

        return hashes

    def _decrypt_history_modern(self, blob: bytes) -> bytes:
        """Decrypt password history using modern AES encryption.

        Args:
            blob: Encrypted history blob.

        Returns:
            Decrypted history data containing multiple hashes.
        """
        crypted = c_ntds_crypto.CRYPTED_HASHW16(blob)

        pek_index = self._get_pek_index_from_header(crypted.Header)
        return self._aes_decrypt(
            self.pek_list[pek_index],
            bytearray(crypted.EncryptedHash[: self.CryptoConstants.NTLM_HASH_SIZE]),
            bytearray(crypted.KeyMaterial),
        )

    def _decode_user_account_control(self, uac: int) -> dict[str, bool]:
        """Decode User Account Control flags.

        Args:
            uac: User Account Control integer value.

        Returns:
            Dictionary mapping flag names to boolean values.
        """
        return {flag.name.lower(): bool(uac & flag.value) for flag in UserAccountControl}

    def _extract_supplemental_info(self, account: User | Computer) -> Iterator[dict[str, str | None]]:
        """Extract and decrypt supplemental credentials (Kerberos keys, cleartext passwords).

        Args:
            account: Account record from the database.

        Yields:
            Dictionary containing supplemental credential information.
        """
        try:
            supplemental_credentials = account.supplementalCredentials
        except KeyError:
            yield {}
            return

        if supplemental_credentials is None:
            yield {}
            return

        for supplemental_credential in supplemental_credentials:
            info = {}
            if "Primary:CLEARTEXT" in supplemental_credential:
                info["cleartext_password"] = supplemental_credential["Primary:CLEARTEXT"]

            if "Packages" in supplemental_credential:
                info["packages"] = supplemental_credential["Packages"]

            if "Primary:WDigest" in supplemental_credential:
                info["w_digest"] = "".join(supplemental_credential["Primary:WDigest"])

            if not {"Primary:Kerberos", "Primary:Kerberos-Newer-Keys"}.intersection(supplemental_credential):
                yield info
                return

            for key_information in self._extract_kerberos_keys(supplemental_credential["Primary:Kerberos-Newer-Keys"]):
                key_information.update(info)
                yield key_information

    def _extract_kerberos_keys(self, kerberos_keys: dict[str, Any]) -> Iterator[dict[str, str | None]]:
        """Extract Kerberos keys from property value.

        Args:
            kerberos_keys: ``dict`` Kerberos keys.

        Yields:
            Dictionary containing Kerberos key information.
        """
        # Extract default salt if present
        default_salt = None
        if "DefaultSalt" in kerberos_keys:
            default_salt = kerberos_keys["DefaultSalt"].hex()

        default_iteration_count = None
        if "DefaultIterationCount" in kerberos_keys:
            default_iteration_count = kerberos_keys["DefaultIterationCount"]

        # Process all key entries
        credential_types = {
            "Credentials",
            "ServiceCredentials",
            "OldCredentials",
            "OlderCredentials",
        }

        for credential_type in credential_types:
            if credential_type not in kerberos_keys:
                continue

            for key in kerberos_keys[credential_type]:
                key_information = {
                    "default_salt": default_salt,
                    "default_iteration_count": default_iteration_count,
                }

                key_information["credential_type"] = credential_type
                key_information["kerberos_key"] = key["Key"].hex()
                key_information["kerberos_type"] = KERBEROS_TYPE.get(key["KeyType"], str(key["KeyType"]))
                key_information["iteration_count"] = key["IterationCount"]
                key_information["default_salt"] = default_salt

                yield key_information

    def extract_generic_account_info(self, account: User | Computer) -> Iterator[dict[str, Any]]:
        """Convert a database account record to NTDS account secret records.

        Args:
            account: Account object from the database.

        Yields:
            NtdsUserSecretRecord containing decrypted credentials.
        """
        self.target.log.debug("Decrypting hash for user: %s", account.name)

        # Decrypt password hashes
        try:
            lm_hash = self._decrypt_hash(account.dBCSPwd, account.rid, True)
        except KeyError:
            lm_hash = self.CryptoConstants.DEFAULT_LM_HASH

        try:
            nt_hash = self._decrypt_hash(account.unicodePwd, account.rid, False)
        except KeyError:
            nt_hash = self.CryptoConstants.DEFAULT_NT_HASH

        # Decrypt password histories
        try:
            lm_history = self._decrypt_history(account.lmPwdHistory, account.rid)
        except KeyError:
            lm_history = None

        try:
            nt_history = self._decrypt_history(account.ntPwdHistory, account.rid)
        except KeyError:
            nt_history = None

        # Decode UAC flags
        uac_flags = self._decode_user_account_control(account.user_account_control)

        # Peripheral information
        try:
            upn = account.userPrincipalName
        except KeyError:
            upn = None

        try:
            description = account.description
        except KeyError:
            description = None

        try:
            admin_count = bool(account.adminCount)
        except KeyError:
            admin_count = False

        try:
            member_of = [group.distinguished_name for group in account.groups()]
        except KeyError:
            member_of = None

        try:
            service_principal_name = (
                [account.servicePrincipalName]
                if isinstance(account.servicePrincipalName, str)
                else account.servicePrincipalName
            )
        except KeyError:
            service_principal_name = None

        # Extract supplemental credentials and yield records
        for supplemental_info in self._extract_supplemental_info(account):
            yield dict(
                common_name=account.cn,
                upn=upn,
                sam_name=account.sam_account_name,
                sam_type=SAM_ACCOUNT_TYPE_INTERNAL_TO_NAME[account.sAMAccountType].lower(),
                description=description,
                sid=account.sid,
                rid=account.rid,
                password_last_set=account.pwdLastSet,
                logon_last_failed=account.badPasswordTime,
                logon_last_success=account.instance_type,
                account_expires=account.accountExpires if isinstance(account.accountExpires, datetime) else None,
                creation_time=account.when_created,
                last_modified_time=account.when_changed,
                admin_count=admin_count,
                is_deleted=account.is_deleted,
                lm=lm_hash,
                lm_history=lm_history,
                nt=nt_hash,
                nt_history=nt_history,
                **supplemental_info,
                user_account_control=account.user_account_control,
                **uac_flags,
                object_classes=account.object_class,
                distinguished_name=account.distinguished_name,
                object_guid=account.guid,
                primary_group_id=account.primary_group_id,
                member_of=member_of,
                service_principal_name=service_principal_name,
            )

    @export(record=NtdsUserAccountRecord, description="Extract user accounts & thier sercrets from NTDS.dit database")
    def user_accounts(self) -> Iterator[NtdsUserAccountRecord]:
        """Extract all user account from the NTDS.dit database.

        Yields:
            ``NtdsUserAccountRecord``: for each user account found in the database.
        """
        for account in self.ntds.users():
            for generic_info in self.extract_generic_account_info(account):
                # TODO: Fix the extraction here
                try:
                    info = account.info
                except KeyError:
                    info = None

                try:
                    comment = account.comment
                except KeyError:
                    comment = None

                try:
                    telephone_number = account.telephoneNumber
                except KeyError:
                    telephone_number = None

                try:
                    home_directory = account.homeDirectory
                except KeyError:
                    home_directory = None

                yield NtdsUserAccountRecord(
                    **generic_info,
                    info=info,
                    comment=comment,
                    telephone_number=telephone_number,
                    home_directory=home_directory,
                    _target=self.target,
                )

    @export(
        record=NtdsComputerAccountRecord,
        description="Extract computer accounts & thier sercrets from NTDS.dit database",
    )
    def computer_accounts(self) -> Iterator[NtdsComputerAccountRecord]:
        """Extract all computer account from the NTDS.dit database.

        Yields:
            ``NtdsComputerAccountRecord``: for each computer account found in the database.
        """
        for account in self.ntds.computers():
            for generic_info in self.extract_generic_account_info(account):
                try:
                    dns_hostname = account.dNSHostName
                except KeyError:
                    dns_hostname = None

                try:
                    operating_system = account.operatingSystem
                except KeyError:
                    operating_system = None

                try:
                    operating_system_version = account.operatingSystemVersion
                except KeyError:
                    operating_system_version = None

                yield NtdsComputerAccountRecord(
                    **generic_info,
                    dns_hostname=dns_hostname,
                    operating_system=operating_system,
                    operating_system_version=operating_system_version,
                    _target=self.target,
                )
