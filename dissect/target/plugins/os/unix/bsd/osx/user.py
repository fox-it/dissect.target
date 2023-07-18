import plistlib
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

AccountPolicyRecord = TargetRecordDescriptor(
    "osx/account_policy",
    [
        ("string", "user"),
        ("string", "generateduid"),
        ("datetime", "creation_time"),
        ("datetime", "password_last_time"),
        ("datetime", "failed_login_time"),
        ("varint", "failed_login_count"),
        ("path", "source"),
    ],
)


class UserPlugin(Plugin):
    # TODO: Parse additional user data like: HeimdalSRPKey, KerberosKeys, ShadowHashData, LinkedIdentity,
    # inputSources, smartCardSecureTokenData, smartCardSecureTokenUUID, unlockOptions, smb_sid

    USER_PATH = "/var/db/dslocal/nodes/Default/users"
    USER_GLOB = "/var/db/dslocal/nodes/Default/users/*.plist"

    def check_compatible(self) -> bool:
        return self.target.fs.path(self.USER_PATH).exists()

    @export(record=AccountPolicyRecord)
    def account_policy(self) -> Iterator[AccountPolicyRecord]:
        for path in self.target.fs.glob(self.USER_GLOB):
            user = plistlib.load(self.target.fs.path(path).open("rb"))

            if user.get("accountPolicyData"):
                for index in range(len(user.get("accountPolicyData"))):
                    account_policy = plistlib.loads(user.get("accountPolicyData")[index])

                    yield AccountPolicyRecord(
                        user=user.get("name", [None])[0],
                        generateduid=user.get("generateduid", [None])[0],
                        creation_time=account_policy.get("creationTime"),
                        password_last_time=account_policy.get("passwordLastSetTime"),
                        failed_login_count=account_policy.get("failedLoginCount"),
                        failed_login_time=account_policy.get("failedLoginTimestamp"),
                        source=path,
                    )
