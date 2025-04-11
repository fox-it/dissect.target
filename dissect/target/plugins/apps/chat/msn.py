from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree as ET

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.apps.chat.chat import (
    ChatAttachmentRecord,
    ChatMessageRecord,
    ChatPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


class MSNPlugin(ChatPlugin):
    """Microsoft MSN Messenger plugin.

    Supports the following versions on Windows XP and Windows 7:
        - Windows Live Messenger (WLM) 2009
        - MSN 7.5

    Other versions might work but have not been tested. Does not support ``Messenger Plus! Live`` artifacts.
    Tested using Escargot (https://escargot.chat).

    Resources:
        - https://en.wikipedia.org/wiki/Microsoft_Messenger_service
        - https://en.wikipedia.org/wiki/MSN_Messenger
        - http://computerforensics.parsonage.co.uk/downloads/MSNandLiveMessengerArtefactsOfConversations.pdf
    """

    __namespace__ = "msn"

    DATA_PATH = "Application Data\\Microsoft\\MSN Messenger"
    HIST_PATH = "My Documents\\My Received Files"

    def __init__(self, target: Target):
        super().__init__(target)
        self.installs = list(self.find_installs())

    def find_installs(self) -> Iterator[tuple[UserDetails, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            if (path := self.target.fs.path(user_details.user.home).joinpath(self.DATA_PATH)).exists():
                for profile in path.iterdir():
                    if profile.is_dir():
                        yield user_details, profile

    def check_compatible(self) -> None:
        if not self.installs:
            raise UnsupportedPluginError("No Microsoft MSN installs found on target")

    @export(record=[ChatMessageRecord, ChatAttachmentRecord])
    def history(self) -> Iterator[ChatMessageRecord | ChatAttachmentRecord]:
        """Yield MSN chat history messages.

        Chat history artifacts can be found in:
            - ``$HOME/My Documents/My Received Files/MsnMsgr.txt``
            - ``$HOME/My Documents/My Received Files/$username$PassportID/History/*.xml``
        """

        for user_details, profile in self.installs:
            if not (hist_root := self.target.fs.path(user_details.user.home).joinpath(self.HIST_PATH)).exists():
                self.target.log.warning(
                    "User %s does not have saved MSN chat history: directory %s does not exist",
                    user_details.user.name,
                    hist_root,
                )
                continue

            hist_dir = None
            for item in hist_root.iterdir():
                if item.is_dir() and (hist_dir := item.name).endswith(profile.name):
                    for hist_file in hist_root.joinpath(hist_dir).joinpath("History").glob("*.xml"):
                        try:
                            xml = ET.fromstring(hist_file.read_text())
                        except Exception as e:
                            self.target.log.warning("XML file %s is malformed: %s", hist_file, e)
                            continue

                        for entry in xml:
                            common = {
                                "ts": entry.attrib.get("DateTime", 0),
                                "client": self.__namespace__,
                                "account": profile.name,
                                "sender": entry.find(".//From/User").get("FriendlyName"),
                                "_user": user_details.user,
                                "_target": self.target,
                            }

                            if entry.tag == "Message":
                                yield ChatMessageRecord(
                                    **common,
                                    recipient=entry.find(".//To/User").get("FriendlyName"),
                                    message=entry.find(".//Text").text,
                                )

                            elif (
                                entry.tag in ["Invitation", "InvitationResponse"]
                                and (file := entry.find(".//File")) is not None
                            ):
                                yield ChatAttachmentRecord(
                                    **common,
                                    recipient=None,  # unknown with Invitations
                                    attachment=file.text,
                                    description=entry.find(".//Text").text,
                                )


def convert_email(string: str) -> int:
    """Convert MSN email address to 10 digit Passport ID."""
    num = 0
    for char in string.lower():
        num = num * 101 + ord(char)
        num -= (num // 4294967296) * 4294967296
    return num
