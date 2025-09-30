from __future__ import annotations

from binascii import hexlify, unhexlify
from hashlib import md5
from struct import unpack
from typing import TYPE_CHECKING

from Cryptodome.Cipher import AES, ARC4, DES
from dissect.cstruct import cstruct
from dissect.esedb import EseDB
from dissect.util import ts
from dissect.util.sid import read_sid

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export
from dissect.target.plugins.os.windows.credential.sam import rid_to_key

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct.types import structure
    from flow.record import Record

    from dissect.target.target import Target


# User Account Control flags mapping
UAC_FLAGS = {
    0x0001: "script",
    0x0002: "account_disable",
    0x0008: "home_dir_required",
    0x0010: "lockout",
    0x0020: "passwd_not_reqd",
    0x0040: "passwd_cant_change",
    0x0080: "encrypted_text_pwd_allowed",
    0x0100: "temp_duplicate_account",
    0x0200: "normal_account",
    0x0800: "interdomain_trust_account",
    0x1000: "workstation_trust_account",
    0x2000: "server_trust_account",
    0x10000: "dont_expire_password",
    0x20000: "mns_logon_account",
    0x40000: "smartcard_required",
    0x80000: "trusted_for_delegation",
    0x100000: "not_delegated",
    0x200000: "use_des_key_only",
    0x400000: "dont_req_preauth",
    0x800000: "password_expired",
    0x1000000: "trusted_to_auth_for_delegation",
    0x04000000: "partial_secrets_account",
}

# NTDS attribute name to internal field mapping
NAME_TO_INTERNAL = {
    "usn_created": "ATTq131091",
    "usn_changed": "ATTq131192",
    "name": "ATTm3",
    "object_guid": "ATTk589826",
    "object_sid": "ATTr589970",
    "user_account_control": "ATTj589832",
    "primary_group_id": "ATTj589922",
    "account_expires": "ATTq589983",
    "logon_count": "ATTj589993",
    "sam_account_name": "ATTm590045",
    "sam_account_type": "ATTj590126",
    "last_logon_timestamp": "ATTq589876",
    "user_principal_name": "ATTm590480",
    "unicode_pwd": "ATTk589914",
    "dbcspwd": "ATTk589879",
    "nt_pwd_history": "ATTk589918",
    "lm_pwd_history": "ATTk589984",
    "pek_list": "ATTk590689",
    "supplemental_credentials": "ATTk589949",
    "password_last_set": "ATTq589920",
    "instance_type": "ATTj131073",
}

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

# Record descriptor for NTDS user secrets
NtdsUserSecretRecord = TargetRecordDescriptor(
    "windows/credential/ntds",
    [
        ("string", "upn"),
        ("string", "sam_name"),
        ("datetime", "password_last_set"),
        ("string", "lm"),
        ("string[]", "lm_history"),
        ("string", "nt"),
        ("string[]", "nt_history"),
        *[("boolean", flag) for flag in UAC_FLAGS.values()],
        ("string", "cleartext_password"),
        ("string", "credential_type"),
        ("string", "kerberos_type"),
        ("string", "kerberos_key"),
        ("string", "default_salt"),
        ("uint32", "iteration_count"),
    ],
)


class CryptoStructures:
    """Container for C structure definitions used in NTDS crypto operations."""

    # Dynamic structure templates
    PEK_LIST_ENC_DEF = """
    typedef struct {{
        CHAR Header[8];
        CHAR KeyMaterial[16];
        BYTE EncryptedPek[{Length}];
    }} PEKLIST_ENC;
    """

    PEK_LIST_PLAIN_DEF = """
    typedef struct {{
        CHAR Header[32];
        BYTE DecryptedPek[{Length}];
    }} PEKLIST_PLAIN;
    """

    CRYPTED_HASH_W16_DEF = """
    typedef struct {{
        BYTE Header[8];
        BYTE KeyMaterial[16];
        DWORD Unknown;
        BYTE EncryptedHash[{Length}];
    }} CRYPTED_HASHW16;
    """

    CRYPTED_HISTORY_DEF = """
    typedef struct {{
        BYTE Header[8];
        BYTE KeyMaterial[16];
        BYTE EncryptedHash[{Length}];
    }} CRYPTED_HISTORY;
    """

    CRYPTED_BLOB_DEF = """
    typedef struct {{
        BYTE Header[8];
        BYTE KeyMaterial[16];
        BYTE EncryptedHash[{Length}];
    }} CRYPTED_BLOB;
    """

    # Static structures
    NTDS_CRYPTO_DEF = """
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

    SAMR_STRUCTS_DEF = """
    typedef struct {
        uint16 NameLength;
        uint16 ValueLength;
        uint16 Reserved;
        char   PropertyName[NameLength];
        char   PropertyValue[ValueLength];
    } USER_PROPERTY;

    typedef struct {
        uint32 Reserved1;
        uint32 Length;
        uint16 Reserved2;
        uint16 Reserved3;
        BYTE   Reserved4[96];
        uint16 PropertySignature;
        uint16 PropertyCount;
        USER_PROPERTY UserProperties[PropertyCount];
    } USER_PROPERTIES;

    typedef struct {
        uint16 Reserved1;
        uint16 Reserved2;
        uint32 Reserved3;
        uint32 IterationCount;
        uint32 KeyType;
        uint32 KeyLength;
        uint32 KeyOffset;
    } KERB_KEY_DATA_NEW;

    typedef struct {
        uint16 Revision;
        uint16 Flags;
        uint16 CredentialCount;
        uint16 ServiceCredentialCount;
        uint16 OldCredentialCount;
        uint16 OlderCredentialCount;
        uint16 DefaultSaltLength;
        uint16 DefaultSaltMaximumLength;
        uint32 DefaultSaltOffset;
        uint32 DefaultIterationCount;
        KERB_KEY_DATA_NEW Credentials[CredentialCount];
        KERB_KEY_DATA_NEW ServiceCredentials[ServiceCredentialCount];
        KERB_KEY_DATA_NEW OldCredentials[OldCredentialCount];
        KERB_KEY_DATA_NEW OlderCredentials[OlderCredentialCount];
    } KERB_STORED_CREDENTIAL_NEW;
    """


# Initialize cstruct parsers
c_ntds_crypto = cstruct().load(CryptoStructures.NTDS_CRYPTO_DEF)
c_samr = cstruct().load(CryptoStructures.SAMR_STRUCTS_DEF)


class NtdsPlugin(Plugin):
    """Plugin to parse NTDS.dit Active Directory database and extract user credentials.

    This plugin decrypts and extracts user password hashes, password history,
    Kerberos keys, and other authentication data from the NTDS.dit database
    found on Windows Domain Controllers.
    """

    __namespace__ = "ntds"

    # Struct constants
    class StructConstant:
        """Constants used for struct operations."""

        PEK_LIST_ENC_LENGTH = len(cstruct().load(CryptoStructures.PEK_LIST_ENC_DEF.format(Length=0)).PEKLIST_ENC)
        PEK_LIST_PLAIN_LENGTH = len(cstruct().load(CryptoStructures.PEK_LIST_PLAIN_DEF.format(Length=0)).PEKLIST_PLAIN)
        CRYPTED_HASH_W16_LENGTH = len(
            cstruct().load(CryptoStructures.CRYPTED_HASH_W16_DEF.format(Length=0)).CRYPTED_HASHW16
        )
        CRYPTED_HISTORY_LENGTH = len(
            cstruct().load(CryptoStructures.CRYPTED_HISTORY_DEF.format(Length=0)).CRYPTED_HISTORY
        )
        CRYPTED_BLOB_LENGTH = len(cstruct().load(CryptoStructures.CRYPTED_BLOB_DEF.format(Length=0)).CRYPTED_BLOB)

    # Encryption and crypto constants
    class CryptoConstants:
        """Constants used for cryptographic operations."""

        PEK_LIST_ENTRY_SIZE = 20
        DES_BLOCK_SIZE = 8
        IV_SIZE = 16
        NTLM_HASH_SIZE = 16

        # The header contains the PEK index encoded in the hex representation of the header bytes.
        PEK_INDEX_HEX_START = 8
        PEK_INDEX_HEX_END = 10

        # Number of MD5 iterations used when deriving the RC4 key for older PEK lists.
        PEK_KEY_DERIVATION_ITERATIONS = 1000

        # First 4 bytes are a version/marker, not ciphertext
        AES_HASH_HEADER_SIZE = 4

        # Version-specific headers
        UP_TO_WINDOWS_2012_R2_PEK_HEADER = b"\x02\x00\x00\x00"
        WINDOWS_2016_TP4_PEK_HEADER = b"\x03\x00\x00\x00"
        WINDOWS_2016_TP4_HASH_HEADER = b"\x13\x00\x00\x00"

        # Default values
        DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
        DEFAULT_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
        EMPTY_BYTE = b"\x00"
        DEFAULT_AES_IV = b"\x00" * 16

    # SAM account type constants
    class AccountTypes:
        """SAM account type constants."""

        NORMAL_USER = 0x30000000
        MACHINE = 0x30000001
        TRUST = 0x30000002
        ALL_TYPES = (NORMAL_USER, MACHINE, TRUST)

    # Other constants
    OBJECT_IS_WRITEABLE_ON_THIS_DIRECTORY = 4

    def __init__(self, target: Target):
        """Initialize the NTDS plugin.

        Args:
            target: The target system to analyze.
        """
        super().__init__(target)
        self.ntds_path = self.target.fs.path("/sysvol/Windows/NTDS/ntds.dit")
        self._pek_list: list[bytes] = []
        self.ntds_database = None
        self._filter_fields = self._get_filter_fields()

    def _get_filter_fields(self) -> set[str]:
        """Get the set of fields to filter for when scanning the database.

        Returns:
            Set of internal field names to filter records by.
        """
        return {
            NAME_TO_INTERNAL["object_sid"],
            NAME_TO_INTERNAL["dbcspwd"],
            NAME_TO_INTERNAL["name"],
            NAME_TO_INTERNAL["sam_account_type"],
            NAME_TO_INTERNAL["unicode_pwd"],
            NAME_TO_INTERNAL["sam_account_name"],
            NAME_TO_INTERNAL["user_principal_name"],
            NAME_TO_INTERNAL["nt_pwd_history"],
            NAME_TO_INTERNAL["lm_pwd_history"],
            NAME_TO_INTERNAL["password_last_set"],
            NAME_TO_INTERNAL["user_account_control"],
            NAME_TO_INTERNAL["supplemental_credentials"],
            NAME_TO_INTERNAL["pek_list"],
            NAME_TO_INTERNAL["instance_type"],
        }

    def check_compatible(self) -> None:
        """Check if the plugin can run on the target system.

        Raises:
            UnsupportedPluginError: If NTDS.dit is not found or system hive is missing.
        """
        if not self.ntds_path.exists():
            raise UnsupportedPluginError("NTDS.dit file not found")

        if not self.target.has_function("lsa") or not hasattr(self.target.lsa, "syskey"):
            raise UnsupportedPluginError("System Hive is not present or LSA function not available")

    def _collect_pek_and_user_records(self) -> tuple[bytes, list[Record]]:
        """Scan the ESE database and extract PEK list and user records.

        Returns:
            Tuple containing:
                - Raw PEK list blob (bytes)
                - List of user records from the database
        """
        db = EseDB(self.ntds_path.open(), False)
        pek_blob = None
        user_records: list[Record] = []

        for table in db.tables():
            for record in table.records():
                try:
                    columns = record.as_dict().keys()
                except TypeError:
                    continue

                if not self._filter_fields.intersection(columns):
                    continue

                # Extract PEK list if present
                if record[NAME_TO_INTERNAL["pek_list"]]:
                    pek_blob = record[NAME_TO_INTERNAL["pek_list"]]

                # Collect user records that are writable and of valid account type
                if self._is_valid_user_record(record):
                    user_records.append(record)

        self.ntds_database = db
        return pek_blob, user_records

    def _is_valid_user_record(self, record: Record) -> bool:
        """Check if a record represents a valid user account.

        Args:
            record: Database record to check.

        Returns:
            True if the record is a valid user account, False otherwise.
        """
        return (
            record[NAME_TO_INTERNAL["sam_account_type"]] in self.AccountTypes.ALL_TYPES
            and record[NAME_TO_INTERNAL["instance_type"]] & self.OBJECT_IS_WRITEABLE_ON_THIS_DIRECTORY
        )

    def _parse_and_decrypt_pek_list(self, pek_blob: bytes) -> None:
        """Parse PEK list structure and decrypt PEK keys.

        Args:
            pek_blob: Raw PEK list blob from the database.
        """
        # Create structure with correct size
        enc_struct = cstruct().load(
            CryptoStructures.PEK_LIST_ENC_DEF.format(Length=len(pek_blob) - self.StructConstant.PEK_LIST_ENC_LENGTH)
        )
        pek_list_enc = enc_struct.PEKLIST_ENC(pek_blob)

        header = bytearray(pek_list_enc.Header)

        if header.startswith(self.CryptoConstants.UP_TO_WINDOWS_2012_R2_PEK_HEADER):
            self._decrypt_pek_legacy(pek_list_enc)
        elif header.startswith(self.CryptoConstants.WINDOWS_2016_TP4_PEK_HEADER):
            self._decrypt_pek_modern(pek_list_enc)
        else:
            self.target.log.error("Unknown PEK list header: %s", header)

    def _decrypt_pek_modern(self, pek_list_enc: structure) -> None:
        """Decrypt PEK list for Windows Server 2016+ using AES encryption.

        Args:
            pek_list_enc: Encrypted PEK list structure.
        """
        # Decrypt using AES with syskey as key and KeyMaterial as IV
        pek_plain_raw = self._aes_decrypt(
            self.target.lsa.syskey, bytearray(pek_list_enc.EncryptedPek), pek_list_enc.KeyMaterial
        )

        # Parse decrypted structure
        plain_struct = cstruct().load(
            CryptoStructures.PEK_LIST_PLAIN_DEF.format(
                Length=len(pek_plain_raw) - self.StructConstant.PEK_LIST_PLAIN_LENGTH
            )
        )
        plain = plain_struct.PEKLIST_PLAIN(pek_plain_raw)

        # Extract PEK entries (4-byte index + 16-byte key)
        self._extract_pek_entries(plain.DecryptedPek)

    def _decrypt_pek_legacy(self, pek_list_enc: structure) -> None:
        """Decrypt PEK list for Windows Server 2012 R2 and earlier using RC4.

        Args:
            pek_list_enc: Encrypted PEK list structure.
        """
        # Derive RC4 key from syskey and KeyMaterial
        rc4_key = self._derive_rc4_key(
            self.target.lsa.syskey, pek_list_enc.KeyMaterial, self.CryptoConstants.PEK_KEY_DERIVATION_ITERATIONS
        )

        # Decrypt with RC4
        rc4 = ARC4.new(rc4_key)
        pek_plain_raw = rc4.encrypt(bytearray(pek_list_enc.EncryptedPek))

        # Parse decrypted structure
        plain_struct = cstruct().load(
            CryptoStructures.PEK_LIST_PLAIN_DEF.format(
                Length=len(pek_plain_raw) - self.StructConstant.PEK_LIST_PLAIN_LENGTH
            )
        )
        plain = plain_struct.PEKLIST_PLAIN(pek_plain_raw)

        # Extract PEK keys from legacy format
        pek_key_len = len(c_ntds_crypto.PEK_KEY)
        for i in range(0, len(plain.DecryptedPek), pek_key_len):
            pek_key = c_ntds_crypto.PEK_KEY(plain.DecryptedPek[i : i + pek_key_len]).Key
            self._pek_list.append(pek_key)
            self.target.log.info("PEK #%d decrypted: %s", i // pek_key_len, hexlify(pek_key).decode())

    def _extract_pek_entries(self, data: bytes) -> None:
        """Extract PEK entries from decrypted data.

        PEK entries are stored as: [4-byte index][16-byte key]
        The list is terminated by a non-sequential index.

        Args:
            data: Decrypted PEK data containing entries.
        """
        entry_size = self.CryptoConstants.PEK_LIST_ENTRY_SIZE
        pos, expected_index = 0, 0

        while pos + entry_size <= len(data):
            pek_entry = data[pos : pos + entry_size]
            index, pek = unpack("<L16s", bytearray(pek_entry))

            # Non-sequential index marks end of list
            if index != expected_index:
                # Adjust pos so while condition fails next iteration
                pos = len(data)
                continue

            self._pek_list.append(pek)
            self.target.log.info("PEK #%d found and decrypted: %s", index, hexlify(pek).decode())

            expected_index += 1
            pos += entry_size

        if pos < len(data):
            self.target.log.warning("PEK list contained extra data after terminator")

    def _derive_rc4_key(self, syskey: bytes, key_material: bytes, iterations: int) -> bytes:
        """Derive RC4 key using MD5 with multiple iterations.

        Args:
            syskey: System key from LSA.
            key_material: Random key material for this encryption.
            iterations: Number of MD5 iterations to perform.

        Returns:
            16-byte RC4 key.
        """
        hasher = md5()
        hasher.update(syskey)
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
            self._pek_list[pek_index],
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

    def _decrypt_hash(self, blob: bytes, rid: int, is_lm: bool) -> str:
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
        struct_w16 = cstruct().load(
            CryptoStructures.CRYPTED_HASH_W16_DEF.format(Length=len(blob) - self.StructConstant.CRYPTED_HASH_W16_LENGTH)
        )
        crypted = struct_w16.CRYPTED_HASHW16(blob)

        # Decrypt AES layer
        pek_index = self._get_pek_index_from_header(crypted.Header)
        decrypted = self._aes_decrypt(
            self._pek_list[pek_index],
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
        struct_hist = cstruct().load(
            CryptoStructures.CRYPTED_HISTORY_DEF.format(Length=len(blob) - self.StructConstant.CRYPTED_HISTORY_LENGTH)
        )
        crypted = struct_hist.CRYPTED_HISTORY(blob)
        header_bytes = bytearray(crypted.Header)

        if header_bytes.startswith(self.CryptoConstants.WINDOWS_2016_TP4_HASH_HEADER):
            # Modern AES encryption
            decrypted = self._decrypt_history_modern(blob, rid)
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

    def _decrypt_history_modern(self, blob: bytes, rid: int) -> bytes:
        """Decrypt password history using modern AES encryption.

        Args:
            blob: Encrypted history blob.
            rid: User's relative ID.

        Returns:
            Decrypted history data containing multiple hashes.
        """
        struct_w16 = cstruct().load(
            CryptoStructures.CRYPTED_HASH_W16_DEF.format(Length=len(blob) - self.StructConstant.CRYPTED_HASH_W16_LENGTH)
        )
        crypted = struct_w16.CRYPTED_HASHW16(blob)

        pek_index = self._get_pek_index_from_header(crypted.Header)
        return self._aes_decrypt(
            self._pek_list[pek_index],
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
        return {flag_name: bool(uac & flag_bit) for flag_bit, flag_name in UAC_FLAGS.items()}

    def _decrypt_supplemental_info(self, record: Record) -> Iterator[dict[str, str | None]]:
        """Extract and decrypt supplemental credentials (Kerberos keys, cleartext passwords).

        Args:
            record: User record from database.

        Yields:
            Dictionary containing supplemental credential information.
        """
        default_info = {
            "cleartext_password": None,
            "kerberos_type": None,
            "kerberos_key": None,
            "default_salt": None,
            "iteration_count": None,
            "credential_type": None,
        }

        blob = record[NAME_TO_INTERNAL["supplemental_credentials"]]
        if not blob or len(blob) < self.StructConstant.CRYPTED_BLOB_LENGTH:
            yield default_info
            return

        # Decrypt the supplemental blob
        decrypted = self._decrypt_supplemental_blob(blob)
        if not decrypted:
            yield default_info
            return

        # Parse USER_PROPERTIES structure
        try:
            user_properties = c_samr.USER_PROPERTIES(decrypted)
        except Exception:
            # Some old W2K3 systems have non-standard properties
            self.target.log.warning("Failed to parse USER_PROPERTIES structure")
            yield default_info
            return

        # Process each property
        for prop in user_properties.UserProperties:
            property_name = prop.PropertyName.decode("utf-16le")

            if property_name == "Primary:CLEARTEXT":
                info = default_info.copy()
                info["cleartext_password"] = self._extract_cleartext_password(prop.PropertyValue)
                yield info

            elif property_name == "Primary:Kerberos-Newer-Keys":
                yield from self._extract_kerberos_keys(prop.PropertyValue, default_info)

    def _decrypt_supplemental_blob(self, blob: bytes) -> bytes | None:
        """Decrypt the supplemental credentials blob.

        Args:
            blob: Encrypted supplemental credentials blob.

        Returns:
            Decrypted data or None if decryption fails.
        """
        # Parse encrypted structure
        struct_blob = cstruct().load(
            CryptoStructures.CRYPTED_BLOB_DEF.format(Length=len(blob) - self.StructConstant.CRYPTED_BLOB_LENGTH)
        )
        crypted = struct_blob.CRYPTED_BLOB(blob)
        header_bytes = bytearray(crypted.Header)

        if header_bytes.startswith(self.CryptoConstants.WINDOWS_2016_TP4_HASH_HEADER):
            # Modern AES encryption (skip first 4 bytes of EncryptedHash)
            pek_index = self._get_pek_index_from_header(crypted.Header)
            return self._aes_decrypt(
                self._pek_list[pek_index],
                bytearray(crypted.EncryptedHash[self.CryptoConstants.AES_HASH_HEADER_SIZE :]),
                bytearray(crypted.KeyMaterial),
            )
        # Legacy RC4 encryption
        return self._remove_rc4_layer(crypted)

    def _extract_cleartext_password(self, property_value: bytes) -> str | None:
        """Extract cleartext password from property value.

        Args:
            property_value: Raw property value bytes.

        Returns:
            Cleartext password string or None if extraction fails.
        """
        try:
            # Try to unhexlify and decode as UTF-16
            return unhexlify(property_value).decode("utf-16le")
        except (UnicodeDecodeError, Exception):
            try:
                # Fallback to UTF-8
                return property_value.decode("utf-8")
            except Exception:
                return None

    def _extract_kerberos_keys(self, property_value: bytes, default_info: dict) -> Iterator[dict[str, str | None]]:
        """Extract Kerberos keys from property value.

        Args:
            property_value: Raw property value containing Kerberos keys.
            default_info: Default info dictionary template.

        Yields:
            Dictionary containing Kerberos key information.
        """
        try:
            property_buffer = unhexlify(property_value)
            kerb = c_samr.KERB_STORED_CREDENTIAL_NEW(property_buffer)
        except Exception:
            self.target.log.warning("Failed to parse Kerberos credential structure")
            yield default_info
            return

        # Extract default salt if present
        default_salt = None
        if kerb.DefaultSaltLength and kerb.DefaultSaltOffset:
            start = int(kerb.DefaultSaltOffset)
            end = start + int(kerb.DefaultSaltLength)
            if 0 <= start < len(property_buffer) and end <= len(property_buffer):
                default_salt = hexlify(property_buffer[start:end]).decode()

        # Process all key entries
        key_collections = {
            "Credentials": kerb.Credentials,
            "ServiceCredentials": kerb.ServiceCredentials,
            "OldCredentials": kerb.OldCredentials,
            "OlderCredentials": kerb.OlderCredentials,
        }

        for credential_type, entries in key_collections.items():
            for entry in entries:
                if entry.KeyLength <= 0 or entry.KeyOffset <= 0:
                    continue

                if entry.KeyOffset + entry.KeyLength > len(property_buffer):
                    self.target.log.error("Invalid Kerberos key offset/length")
                    continue

                info = default_info.copy()
                info["credential_type"] = credential_type
                info["kerberos_key"] = hexlify(
                    property_buffer[entry.KeyOffset : entry.KeyOffset + entry.KeyLength]
                ).decode()
                info["kerberos_type"] = KERBEROS_TYPE.get(entry.KeyType, str(entry.KeyType))
                info["iteration_count"] = entry.IterationCount
                info["default_salt"] = default_salt

                yield info

    def _record_to_secret(self, record: Record) -> Iterator[NtdsUserSecretRecord]:
        """Convert a database record to NTDS user secret records.

        Args:
            record: User record from the database.

        Yields:
            NtdsUserSecretRecord containing decrypted credentials.
        """
        self.target.log.debug("Decrypting hash for user: %s", record[NAME_TO_INTERNAL["name"]])

        # Extract RID from SID
        sid = read_sid(record[NAME_TO_INTERNAL["object_sid"]], swap_last=True)
        rid = int(sid.split("-").pop())

        # Decrypt password hashes
        lm_hash = self._decrypt_hash(record[NAME_TO_INTERNAL["dbcspwd"]], rid, is_lm=True)
        nt_hash = self._decrypt_hash(record[NAME_TO_INTERNAL["unicode_pwd"]], rid, is_lm=False)

        # Decrypt password histories
        lm_history = self._decrypt_history(record[NAME_TO_INTERNAL["lm_pwd_history"]], rid)
        nt_history = self._decrypt_history(record[NAME_TO_INTERNAL["nt_pwd_history"]], rid)

        # Decode UAC flags
        uac = record[NAME_TO_INTERNAL["user_account_control"]]
        uac_flags = self._decode_user_account_control(uac) if uac else dict.fromkeys(UAC_FLAGS.values())

        # Get password timestamp
        password_ts = (
            ts.wintimestamp(record[NAME_TO_INTERNAL["password_last_set"]])
            if record[NAME_TO_INTERNAL["password_last_set"]]
            else None
        )

        # Extract supplemental credentials and yield records
        for supplemental_info in self._decrypt_supplemental_info(record):
            yield NtdsUserSecretRecord(
                upn=record[NAME_TO_INTERNAL["user_principal_name"]],
                sam_name=record[NAME_TO_INTERNAL["sam_account_name"]],
                password_last_set=password_ts,
                lm=lm_hash,
                lm_history=lm_history,
                nt=nt_hash,
                nt_history=nt_history,
                **uac_flags,
                **supplemental_info,
                _target=self.target,
            )

    @export(record=NtdsUserSecretRecord, description="Extract credentials from NTDS.dit database")
    def secrets(self) -> Iterator[NtdsUserSecretRecord]:
        """Extract and decrypt all user credentials from the NTDS.dit database.

        This function orchestrates the entire extraction process:
        1. Opens and scans the NTDS.dit database
        2. Extracts and decrypts the PEK list using the system key
        3. Uses PEK keys to decrypt user password hashes
        4. Extracts additional credentials like Kerberos keys

        Yields:
            NtdsUserSecretRecord for each user account found in the database.

        Raises:
            ValueError: If PEK list cannot be found in the database.
        """
        # Collect PEK blob and user records from database
        pek_blob, user_records = self._collect_pek_and_user_records()

        if not pek_blob:
            raise ValueError("Couldn't find pek_list in NTDS.dit")

        # Decrypt the PEK list
        self._parse_and_decrypt_pek_list(pek_blob)

        if not self._pek_list:
            self.target.log.error("No PEK keys obtained. Can't decrypt hashes.")
            return

        # Process each user record
        for record in user_records:
            yield from self._record_to_secret(record)
