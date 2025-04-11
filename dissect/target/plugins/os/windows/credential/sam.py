from __future__ import annotations

from hashlib import md5, sha256
from struct import pack

try:
    from Crypto.Cipher import AES, ARC4, DES

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

sam_def = """
struct user_F {
  char      unknown1[8];
  uint64    t_last_login;           /* Time of last login */
  char      unknown2[8];
  uint64    t_last_password_set;    /* Time of last password set */
  char      unknown3[8];
  uint64    t_last_incorrect_login; /* Time of last incorrect password */
  int32     rid;
  char      unknown4[4];
  uint16    ACB_bits;               /* Account type and status flags */
  char      unknown5[2];
  uint16    country_code;
  char      unknown6[2];
  uint16    failedcnt;        /* Count of failed logins, if > than policy it is locked. Resets after successful login */
  uint16    logins;           /* Total logins since creation (max. 0xFFFF = 65535) */
  char      unknown7[0xc];
};

#define ACB_DISABLED   0x0001
#define ACB_HOMDIRREQ  0x0002
#define ACB_PWNOTREQ   0x0004
#define ACB_TEMPDUP    0x0008
#define ACB_NORMAL     0x0010
#define ACB_MNS        0x0020
#define ACB_DOMTRUST   0x0040
#define ACB_WSTRUST    0x0080
#define ACB_SVRTRUST   0x0100
#define ACB_PWNOEXP    0x0200
#define ACB_AUTOLOCK   0x0400

// char *acb_fields[16] = {
//    "Disabled" ,
//    "Homedir req." ,
//    "Passwd not req." ,
//    "Temp. duplicate" ,
//    "Normal account" ,
//    "NMS account" ,
//    "Domain trust act." ,
//    "Wks trust act." ,
//    "Srv trust act" ,
//    "Pwd don't expire" ,
//    "Auto lockout" ,
//    "(unknown 0x08)" ,
//    "(unknown 0x10)" ,
//    "(unknown 0x20)" ,
//    "(unknown 0x40)" ,
//    "(unknown 0x80)" ,
// };


struct user_V {

  int unknown1_1;           /* 0x00 - always zero? */
  int unknown1_2;           /* 0x04 - points to username? */
  int unknown1_3;           /* 0x08 - always 0x02 0x00 0x01 0x00 ? */

  int username_ofs;         /* 0x0c */
  int username_len;         /* 0x10 */

  int unknown2_1;           /* 0x14 - always zero? */

  int fullname_ofs;         /* 0x18 */
  int fullname_len;         /* 0x1c */

  int unknown3_1;           /* 0x20 - always zero? */

  int admin_comment_ofs;    /* 0x24 */
  int admin_comment_len;    /* 0x28 */

  int unknown4_1;           /* 0x2c - alway zero? */

  int user_comment_ofs;     /* 0x30 */
  int user_comment_len;     /* 0x34 */

  int unknown5_1;           /* 0x38 - zero? */
  int unknown5_2;           /* 0x3c - to field 8 bytes before hashes */
  int unknown5_3;           /* 0x40 - zero? or size of above? */
  int unknown5_4;           /* 0x44 - zero? */

  int homedir_ofs;          /* 0x48 */
  int homedir_len;          /* 0x4c */

  int unknown6_1;           /* 0x50 - zero? */

  int drvletter_ofs;        /* 0x54 - drive letter for home dir */
  int drvletter_len;        /* 0x58 - len of above, usually 4   */

  int unknown7_1;           /* 0x5c - zero? */

  int logonscr_ofs;         /* 0x60 - users logon script path */
  int logonscr_len;         /* 0x64 - length of string */

  int unknown8_1;           /* 0x68 - zero? */

  int profilep_ofs;         /* 0x6c - profile path string */
  int profilep_len;         /* 0x70 - profile path stringlen */

  int unknown9_1;           /* 0x74 */

  int workstations_ofs;     /* 0x78 */
  int workstations_len;     /* 0x7c */

  int unknowna_1;          /* 0x80 */

  int allowed_hours_ofs;    /* 0x84 */
  int allowed_hours_len;    /* 0x88 */

  int unknownb_1;          /* 0x8c */
  int unknownb_2;          /* 0x90 - pointer to some place before hashes, after comments */
  int unknownb_3;          /* 0x94 - size of above? */
  int unknownb_4;          /* 0x98 - unknown? always 1? */

  int lmpw_ofs;             /* 0x9c */
  int lmpw_len;             /* 0xa0 */

  int unknownc_1;           /* 0xa4 - zero? */

  int ntpw_ofs;             /* 0xa8 */
  int ntpw_len;             /* 0xac */

  int unknownd_1;           /* 0xb0 */
  int unknownd_2;           /* 0xb4 - points to field after hashes */
  int unknownd_3;           /* 0xb8 - size of above field */
  int unknownd_4;           /* 0xbc - zero? */
  int unknownd_5;           /* 0xc0 - points to field after that */
  int unknownd_6;           /* 0xc4 - size of above */
  int unknownd_7;           /* 0xc8 - zero ? */

  char data[4];             /* Data starts here. All pointers above is relative to this,
                               that is V + 0xCC */
};

struct DOMAIN_ACCOUNT_F {
  uint16 revision;                          /* 0x00 */
  uint16 unknown1_1;                        /* 0x02 */
  uint32 unknown1_2;                        /* 0x04 */
  uint64 creation_time;                     /* 0x08 */
  uint64 domain_modified_count;             /* 0x10 */
  uint64 max_password_age;                  /* 0x18 */
  uint64 min_password_age;                  /* 0x20 */
  uint64 force_logoff;                      /* 0x28 */
  uint64 lock_duration;                     /* 0x30 */
  uint64 lock_observation_window;           /* 0x38 */
  uint64 modified_count_at_last_promotion;  /* 0x40 */
  uint32 next_rid;                          /* 0x48 */
  uint32 password_properties;               /* 0x4c */
  uint16 min_password_length;               /* 0x50 */
  uint16 password_history_length;           /* 0x52 */
  uint16 lockout_threshold;                 /* 0x54 */
  uint16 unknown1_3;                        /* 0x56 */
  uint32 server_state;                      /* 0x58 */
  uint16 server_role;                       /* 0x5c */
  uint16 uas_compability_required;          /* 0x5e */
  uint64 unknown2_1;                        /* 0x60 */
  /* char sam_key[];                           0x70, variable size */
};

struct SAM_KEY {      /* size: 64 */
  uint32 revision;    /* 0x00 */
  uint32 length;      /* 0x04 */
  char salt[16];      /* 0x08 */
  char key[16];       /* 0x18 */
  char checksum[16];  /* 0x28 */
  uint64 reserved;    /* 0x38 */
};

struct SAM_KEY_AES {  /* size: >= 32 */
  uint32 revision;     /* 0x00 */
  uint32 length;       /* 0x04 */
  uint32 checksum_len; /* 0x08 */
  uint32 data_len;     /* 0x0c */
  char salt[16];       /* 0x10 */
  /* char data[];         0x20, variable size */
};

struct SAM_HASH {      /* size: 20 */
  uint16 pek_id;       /* 0x00 */
  uint16 revision;     /* 0x02 */
  /* char hash[16];       0x04, variable size */
};

struct SAM_HASH_AES {  /* size: >=24 */
  uint16 pek_id;        /* 0x00 */
  uint16 revision;      /* 0x02 */
  uint32 data_offset;   /* 0x04 */
  char salt[16];        /* 0x08 */
  /* char data[];          0x18, variable size */
};
"""

c_sam = cstruct().load(sam_def)

SamRecord = TargetRecordDescriptor(
    "windows/credential/sam",
    [
        ("uint32", "rid"),
        ("string", "fullname"),
        ("string", "username"),
        ("string", "admincomment"),
        ("string", "usercomment"),
        ("datetime", "lastlogin"),
        ("datetime", "lastpasswordset"),
        ("datetime", "lastincorrectlogin"),
        ("uint32", "flags"),
        ("uint16", "countrycode"),
        ("uint32", "failedlogins"),
        ("uint32", "logins"),
        ("string", "lm"),
        ("string", "nt"),
    ],
)


def expand_des_key(key: bytes) -> bytes:
    # Expand the key from a 7-byte password key into an 8-byte DES key
    key = bytearray(key[:7]).ljust(7, b"\x00")
    s = bytearray(
        [
            ((key[0] >> 1) & 0x7F) << 1,
            ((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3F)) << 1,
            ((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1F)) << 1,
            ((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0F)) << 1,
            ((key[3] & 0x0F) << 3 | ((key[4] >> 5) & 0x07)) << 1,
            ((key[4] & 0x1F) << 2 | ((key[5] >> 6) & 0x03)) << 1,
            ((key[5] & 0x3F) << 1 | ((key[6] >> 7) & 0x01)) << 1,
            (key[6] & 0x7F) << 1,
        ]
    )
    return bytes(s)


def rid_to_key(rid: int) -> tuple[bytes, bytes]:
    s = rid.to_bytes(4, "little", signed=False)
    k1 = expand_des_key(bytes([s[0], s[1], s[2], s[3], s[0], s[1], s[2]]))
    k2 = expand_des_key(bytes([s[3], s[0], s[1], s[2], s[3], s[0], s[1]]))

    return k1, k2


def decrypt_single_hash(rid: int, samkey: bytes, enc_hash: bytes, apwd: bytes) -> bytes:
    if not enc_hash:
        return b""

    sh = c_sam.SAM_HASH(enc_hash)

    if sh.revision not in [0x01, 0x02]:
        raise ValueError(f"Unsupported LM/NT hash revision encountered: {sh.revision}")

    d1, d2 = (DES.new(k, DES.MODE_ECB) for k in rid_to_key(rid))

    if sh.revision == 0x01:  # LM/NT revision 0x01 involving RC4
        sh_hash = enc_hash[len(c_sam.SAM_HASH) :]
        if not sh_hash:  # Empty hash
            return b""

        rc4_key = md5(samkey + pack("<L", rid) + apwd).digest()
        obfkey = ARC4.new(rc4_key).encrypt(sh_hash)

    else:  # LM/NT revision 0x02 involving AES
        sh = c_sam.SAM_HASH_AES(enc_hash)
        if not sh.data_offset:  # Empty hash
            return b""

        sh_hash = enc_hash[len(c_sam.SAM_HASH_AES) :]
        obfkey = AES.new(samkey, AES.MODE_CBC, sh.salt).decrypt(sh_hash)[:16]

    return d1.decrypt(obfkey[:8]) + d2.decrypt(obfkey[8:])


class SamPlugin(Plugin):
    """SAM plugin.

    References:
        - MS-SAMR Specification
        - Reversing samsrv.dll
        - https://github.com/gentilkiwi/mimikatz
        - https://github.com/skelsec/pypykatz
        - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
    """

    SAM_KEY = "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account"

    def check_compatible(self) -> None:
        if not HAS_CRYPTO:
            raise UnsupportedPluginError("Missing pycryptodome dependency")

        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("LSA plugin is required for SAM plugin")

        if not len(list(self.target.registry.keys(self.SAM_KEY))) > 0:
            raise UnsupportedPluginError(f"Registry key not found: {self.SAM_KEY}")

    def calculate_samkey(self, syskey: bytes) -> bytes:
        aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        anum = b"0123456789012345678901234567890123456789\0"

        f_reg = self.target.registry.key(self.SAM_KEY).value("F").value
        f = c_sam.DOMAIN_ACCOUNT_F(f_reg)
        f_key = f_reg[len(c_sam.DOMAIN_ACCOUNT_F) :]
        fk = c_sam.SAM_KEY(f_key)

        if f.revision not in [0x02, 0x03]:
            raise ValueError(f"Unsupported Domain Account F revision encountered: {f.revision}")

        if fk.revision not in [0x01, 0x02]:
            raise ValueError(f"Unsupported SAM Key Data revision encountered: {fk.revision}")

        if fk.revision == 0x01:  # SAM key revision 0x01 involving RC4 (samsrv.dll: KEDecryptKeyWithRC4)
            rc4_key = md5(fk.salt + aqwerty + syskey + anum).digest()
            samkey_data = ARC4.new(rc4_key).encrypt(fk.key + fk.checksum)
            samkey = samkey_data[:16]
            checksum = samkey_data[16:]

            if checksum != md5(samkey + anum + samkey + aqwerty).digest():
                raise ValueError("SAM key checksum validation failed!")
            return samkey

        # SAM key revision 0x02 involving AES  (samsrv.dll: KEDecryptKeyWithAES)
        fk = c_sam.SAM_KEY_AES(f_key)
        key_data = f_key[len(c_sam.SAM_KEY_AES) : len(c_sam.SAM_KEY_AES) + fk.data_len]
        checksum_data = f_key[
            len(c_sam.SAM_KEY_AES) + fk.data_len : len(c_sam.SAM_KEY_AES) + fk.data_len + fk.checksum_len
        ]
        samkey = AES.new(syskey, AES.MODE_CBC, fk.salt).decrypt(key_data)[:16]
        checksum = AES.new(syskey, AES.MODE_CBC, fk.salt).decrypt(checksum_data)[:32]

        if checksum != sha256(samkey).digest():
            raise ValueError("SAM key checksum validation failed!")
        return samkey

    @export(record=SamRecord)
    def sam(self) -> Iterator[SamRecord]:
        """Dump SAM entries

        The Security Account Manager (SAM) registry hive contains registry keys that store usernames, full names and
        passwords in a hashed format, either an LM or NT hash.

        References:
            - https://en.wikipedia.org/wiki/Security_Account_Manager

        Yields SamRecords with fields:

        .. code-block:: text

            rid (uint32): The RID.
            fullname (string): Parsed fullname.
            username (string): Parsed username.
            admincomment (string): Parsed admin comment.
            usercomment (string): Parsed user comment.
            lastlogin (datetime): Parsed last login date.
            lastpasswordset (datetime): Parsed last password set date.
            lastincorrectlogin (datetime): Parsed last incorrect login date.
            flags (uint32): Parsed flags.
            countrycode (uint16): Parsed country code (international country calling code).
            failedlogins (uint32): Parsed failed logins, reset after sucessful login.
            logins (uint32): Parsed logins (max 0xFFFF = 65535).
            lm (string): Parsed LM-hash.
            nt (string): Parsed NT-hash.
        """

        syskey = self.target.lsa.syskey  # aka. bootkey
        samkey = self.calculate_samkey(syskey)  # aka. hashed bootkey or hbootkey

        almpassword = b"LMPASSWORD\0"
        antpassword = b"NTPASSWORD\0"

        for users_key in self.target.registry.keys(f"{self.SAM_KEY}\\Users"):
            for user_key in users_key.subkeys():
                if user_key.name == "Names":
                    continue

                f = c_sam.user_F(user_key.value("F").value)
                user_v = user_key.value("V").value
                v = c_sam.user_V(user_v)
                v_data = user_v[0xCC:]

                u_username = v_data[v.username_ofs : v.username_ofs + v.username_len].decode("utf-16-le")
                u_fullname = v_data[v.fullname_ofs : v.fullname_ofs + v.fullname_len].decode("utf-16-le")
                u_admin_comment = v_data[v.admin_comment_ofs : v.admin_comment_ofs + v.admin_comment_len].decode(
                    "utf-16-le"
                )
                u_user_comment = v_data[v.user_comment_ofs : v.user_comment_ofs + v.user_comment_len].decode(
                    "utf-16-le"
                )

                u_lmpw = v_data[v.lmpw_ofs : v.lmpw_ofs + v.lmpw_len]
                u_ntpw = v_data[v.ntpw_ofs : v.ntpw_ofs + v.ntpw_len]

                lm_hash = decrypt_single_hash(f.rid, samkey, u_lmpw, almpassword).hex()
                nt_hash = decrypt_single_hash(f.rid, samkey, u_ntpw, antpassword).hex()

                yield SamRecord(
                    rid=f.rid,
                    fullname=u_fullname,
                    username=u_username,
                    admincomment=u_admin_comment,
                    usercomment=u_user_comment,
                    lastlogin=ts.wintimestamp(f.t_last_login),
                    lastpasswordset=ts.wintimestamp(f.t_last_password_set),
                    lastincorrectlogin=ts.wintimestamp(f.t_last_incorrect_login),
                    flags=f.ACB_bits,
                    countrycode=f.country_code,
                    logins=f.logins,
                    failedlogins=f.failedcnt,
                    lm=lm_hash,
                    nt=nt_hash,
                    _target=self.target,
                )
