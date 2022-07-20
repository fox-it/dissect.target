from dissect import cstruct
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.util import ts

SYSKEY_ORDER = [0xB, 0x6, 0x7, 0x1, 0x8, 0xA, 0xE, 0x0, 0x3, 0x5, 0x2, 0xF, 0xD, 0x9, 0xC, 0x4]
SYSKEY_PATH = r"ControlSet001\Control\Lsa\{0}"
SYSKEY_KEYS = ["JD", "Skew1", "GBG", "Data"]

c_sam_def = """
struct user_F {
  char      unknown1[8];
  uint64    t_lockout;      /* Time of lockout */
  char      unknown2[8];
  uint64    t_creation;     /* Time of account creation */
  char      unknown3[8];
  uint64    t_login;        /* Time of last login */
  int32     rid;
  char      unknown4[4];
  uint16    ACB_bits;       /* Account type and status flags */
  char      unknown5[6];
  uint16    failedcnt;      /* Count of failed logins, if > than policy it is locked */
  uint16    logins;         /* Total logins since creation */
  char      unknown6[0xc];
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

  int unknown1_1;      /* 0x00 - always zero? */
  int unknown1_2;      /* 0x04 - points to username? */
  int unknown1_3;      /* 0x08 - always 0x02 0x00 0x01 0x00 ? */

  int username_ofs;    /* 0x0c */
  int username_len;    /* 0x10 */

  int unknown2_1;      /* 0x14 - always zero? */

  int fullname_ofs;    /* 0x18 */
  int fullname_len;    /* 0x1c */

  int unknown3_1;      /* 0x20 - always zero? */

  int comment_ofs;     /* 0x24 */
  int comment_len;     /* 0x28 */

  int unknown4_1;      /* 0x2c - alway zero? */
  int unknown4_2;      /* 0x30 - points 4 or 8 byte field before hashes */
  int unknown4_3;      /* 0x34 - zero? or size? */
  int unknown4_4;      /* 0x38 - zero? */
  int unknown4_5;      /* 0x3c - to field 8 bytes before hashes */
  int unknown4_6;      /* 0x40 - zero? or size of above? */
  int unknown4_7;      /* 0x44 - zero? */

  int homedir_ofs;     /* 0x48 */
  int homedir_len;     /* 0x4c */

  int unknown5_1;      /* 0x50 - zero? */

  int drvletter_ofs;   /* 0x54 - drive letter for home dir */
  int drvletter_len;   /* 0x58 - len of above, usually 4   */

  int unknown6_1;      /* 0x5c - zero? */

  int logonscr_ofs;    /* 0x60 - users logon script path */
  int logonscr_len;    /* 0x64 - length of string */

  int unknown7_1;      /* 0x68 - zero? */

  int profilep_ofs;    /* 0x6c - profile path string */
  int profilep_len;    /* 0x70 - profile path stringlen */

  char unknown7[0x90-0x74]; /* 0x74 */

  int unknown8_1;      /* 0x90 - pointer to some place before hashes, after comments */
  int unknown8_2;      /* 0x94 - size of above? */
  int unknown8_3;      /* 0x98 - unknown? always 1? */

  int lmpw_ofs;        /* 0x9c */
  int lmpw_len;        /* 0xa0 */

  int unknown9_1;      /* 0xa4 - zero? */

  int ntpw_ofs;        /* 0xa8 */
  int ntpw_len;        /* 0xac */

  int unknowna_1;      /* 0xb0 */
  int unknowna_2;      /* 0xb4 - points to field after hashes */
  int unknowna_3;      /* 0xb8 - size of above field */
  int unknowna_4;      /* 0xbc - zero? */
  int unknowna_5;      /* 0xc0 - points to field after that */
  int unknowna_6;      /* 0xc4 - size of above */
  int unknowna_7;      /* 0xc8 - zero ? */

  char data[4];        /* Data starts here. All pointers above is relative to this,
                          that is V + 0xCC */
};
"""
c_sam = cstruct.cstruct()
c_sam.load(c_sam_def)

SamRecord = TargetRecordDescriptor(
    "windows/registry/sam",
    [
        ("uint32", "rid"),
        ("string", "fullname"),
        ("string", "username"),
        ("string", "comment"),
        ("datetime", "lockout"),
        ("datetime", "creation"),
        ("datetime", "lastlogin"),
        ("uint32", "flags"),
        ("uint32", "failedlogins"),
        ("uint32", "logins"),
        ("string", "lm"),
        ("string", "ntlm"),
    ],
)


class SamPlugin(Plugin):
    """SAM plugin."""

    KEY = "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users"

    def check_compatible(self):
        if not len(list(self.target.registry.key(self.KEY))) > 0:
            raise UnsupportedPluginError(f"Registry key not found: {self.KEY}")

    @export(record=SamRecord)
    def sam(self):
        """Return the content of SAM hive registry keys.

        The Security Account Manager (SAM) registry hive contains registry keys that store usernames, full names and
        passwords in a hashed format, either an LM or NTLM hash.

        Sources:
            - https://en.wikipedia.org/wiki/Security_Account_Manager

        Yields SamRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            rid (uint32): The RID.
            fullname (string): Parsed fullname.
            username (string): Parsed username.
            comment (string): Parsed comment.
            lockout (datetime): Parsed lockout.
            creation (datetime): Parsed lockout.
            lastlogin (datetime): Parsed last login.
            flags (uint32): Parsed flags.
            failedlogins (uint32): Parsed failed logins.
            logins (uint32): Parsed logins.
            lm (string): Parsed LM.
            ntlm (string): Parsed NTLM.
        """
        for users_key in self.target.registry.iterkeys(self.KEY):
            for user_key in users_key.subkeys():
                if user_key.name == "Names":
                    continue

                user_f = user_key.value("F").value
                f = c_sam.user_F(user_f)

                user_v = user_key.value("V").value
                d = c_sam.user_V(user_v)

                u_username = user_v[d.username_ofs + 0xCC : d.username_ofs + 0xCC + d.username_len].decode("utf-16-le")
                u_fullname = user_v[d.fullname_ofs + 0xCC : d.fullname_ofs + 0xCC + d.fullname_len].decode("utf-16-le")
                u_comment = user_v[d.comment_ofs + 0xCC : d.comment_ofs + 0xCC + d.comment_len].decode("utf-16-le")
                u_lmpw = user_v[d.lmpw_ofs + 0xCC : d.lmpw_ofs + 0xCC + d.lmpw_len]
                u_ntpw = user_v[d.ntpw_ofs + 0xCC : d.ntpw_ofs + 0xCC + d.ntpw_len]

                yield SamRecord(
                    rid=f.rid,
                    fullname=u_fullname,
                    username=u_username,
                    comment=u_comment,
                    lockout=ts.wintimestamp(f.t_lockout),
                    creation=ts.wintimestamp(f.t_creation),
                    lastlogin=ts.wintimestamp(f.t_login),
                    flags=f.ACB_bits,
                    logins=f.logins,
                    failedlogins=f.failedcnt,
                    lm=u_lmpw.hex(),
                    ntlm=u_ntpw.hex()[-31:],
                    _target=self.target,
                )
