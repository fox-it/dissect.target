from __future__ import annotations

from binascii import hexlify, unhexlify
from functools import cached_property, lru_cache
from hashlib import md5
from struct import unpack
from typing import TYPE_CHECKING, Any

from Cryptodome.Cipher import AES, ARC4, DES
from dissect.cstruct import cstruct
from dissect.database.ese.ntds import NTDS
from dissect.database.ese.ntds.utils import format_GUID

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export
from dissect.target.plugins.os.windows.credential.sam import rid_to_key

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct.types import structure
    from dissect.database.ese.ntds.objects import Computer, User

    from dissect.target.target import Target


# User Account Control flags mapping
UAC_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
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
    ("uint32", "user_account_control"),
    *[("boolean", flag.lower()) for flag in UAC_FLAGS.values()],
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

        self._pek_list: list[bytes] = []

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

    @lru_cache(maxsize=1)  # noqa: B019
    def _extract_and_decrypt_pek_list(self) -> None:
        """Extract PEK list structure and decrypt PEK keys.

        Raises:
            RuntimeError: If PEK list cannot be found in the database or couldn't extract PEK keys from the PEK list.
        """
        pek_blob = next(self.ntds.lookup(objectCategory="domainDNS")).pekList

        if not pek_blob:
            raise RuntimeError("Couldn't find pek_list in NTDS.dit")

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

        if not self._pek_list:
            raise RuntimeError("No PEK keys obtained. Can't decrypt hashes.")

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
        return {flag_name.lower(): bool(uac & flag_bit) for flag_bit, flag_name in UAC_FLAGS.items()}

    def _decrypt_supplemental_info(self, account: User | Computer) -> Iterator[dict[str, str | None]]:
        """Extract and decrypt supplemental credentials (Kerberos keys, cleartext passwords).

        Args:
            account: Account record from the database.

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

        try:
            blob = account.supplementalCredentials
        except KeyError:
            yield default_info
            return

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

    @staticmethod
    def __extract_sid_and_rid(account: User | Computer) -> tuple[str, int]:
        """Extract the Security Identifier (SID) and Relative Identifier (RID) from a user or computer account.

        The SID is a unique identifier for the security principal in Active Directory.
        The RID is the last component of the SID, which uniquely identifies the account within its domain.

        Args:
            account (User | Computer): The Active Directory account object (User or Computer)
                                       containing the `objectSid` attribute.

        Returns:
            tuple[str, int]: A tuple containing:
                - The full SID as a string (e.g., "S-1-5-21-1234567890-987654321-112233445-1001")
                - The RID as an integer (e.g., 1001)
        """
        rid = int(account.objectSid.split("-")[-1])
        return account.objectSid, rid

    def extract_generic_account_info(self, account: User | Computer) -> Iterator[dict[str, Any]]:
        """Convert a database account record to NTDS account secret records.

        Args:
            account: Account object from the database.

        Yields:
            NtdsUserSecretRecord containing decrypted credentials.
        """
        self.target.log.debug("Decrypting hash for user: %s", account.name)
        sid, rid = self.__extract_sid_and_rid(account)

        # Decrypt password hashes
        try:
            lm_hash = self._decrypt_hash(account.dBCSPwd, rid, True)
        except KeyError:
            lm_hash = self.CryptoConstants.DEFAULT_LM_HASH

        try:
            nt_hash = self._decrypt_hash(account.unicodePwd, rid, False)
        except KeyError:
            nt_hash = self.CryptoConstants.DEFAULT_NT_HASH

        # Decrypt password histories
        try:
            lm_history = self._decrypt_history(account.lmPwdHistory, rid)
        except KeyError:
            lm_history = None

        try:
            nt_history = self._decrypt_history(account.ntPwdHistory, rid)
        except KeyError:
            nt_history = None

        # Decode UAC flags
        uac_flags = self._decode_user_account_control(account.userAccountControl)

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
            is_deleted = account.isDeleted
        except KeyError:
            is_deleted = False

        try:
            admin_count = bool(account.adminCount)
        except KeyError:
            admin_count = False

        try:
            member_of = [group.distinguishedName for group in account.groups()]
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
        for supplemental_info in self._decrypt_supplemental_info(account):
            yield dict(
                common_name=account.cn,
                upn=upn,
                sam_name=account.sAMAccountName,
                sam_type=SAM_ACCOUNT_TYPE_INTERNAL_TO_NAME[account.sAMAccountType].lower(),
                description=description,
                sid=sid,
                rid=rid,
                password_last_set=account.pwdLastSet,
                logon_last_failed=account.badPasswordTime,
                logon_last_success=account.lastLogon,
                account_expires=account.accountExpires if not isinstance(account.accountExpires, float) else None,
                creation_time=account.whenCreated,
                last_modified_time=account.whenChanged,
                admin_count=admin_count,
                is_deleted=is_deleted,
                lm=lm_hash,
                lm_history=lm_history,
                nt=nt_hash,
                nt_history=nt_history,
                **supplemental_info,
                user_account_control=account.userAccountControl,
                **uac_flags,
                object_classes=account.objectClass,
                distinguished_name=account.distinguishedName,
                object_guid=format_GUID(account.objectGUID),
                primary_group_id=account.primaryGroupID,
                member_of=member_of,
                service_principal_name=service_principal_name,
            )

    @export(record=NtdsUserAccountRecord, description="Extract user accounts & thier sercrets from NTDS.dit database")
    def user_accounts(self) -> Iterator[NtdsUserAccountRecord]:
        """Extract all user account from the NTDS.dit database.

        Yields:
            ``NtdsUserAccountRecord``: for each user account found in the database.
        """
        self._extract_and_decrypt_pek_list()

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
        self._extract_and_decrypt_pek_list()

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
