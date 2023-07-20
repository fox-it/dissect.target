import plistlib
from typing import Iterator

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

AccountPolicyRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "osx/account_policy",
    [
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

    def check_compatible(self) -> bool:
        return self.target.fs.path(self.USER_PATH).exists()

    @export(record=AccountPolicyRecord)
    def account_policy(self) -> Iterator[AccountPolicyRecord]:
        # The data is not retrieved from the home folder of the user
        for user_details in self.target.user_details.all():
            user = plistlib.loads(self.target.fs.path(user_details.user.source).read_bytes())

            if user.get("accountPolicyData"):
                generateduid = user.get("generateduid", [None])[0]

                for account_policy in user.get("accountPolicyData", []):
                    account_policy = plistlib.loads(account_policy)

                    yield AccountPolicyRecord(
                        generateduid=generateduid,
                        creation_time=account_policy.get("creationTime"),
                        password_last_time=account_policy.get("passwordLastSetTime"),
                        failed_login_count=account_policy.get("failedLoginCount"),
                        failed_login_time=account_policy.get("failedLoginTimestamp"),
                        source=user_details.user.source,
                        _user=user_details.user,
                        _target=self.target,
                    )
