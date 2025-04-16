from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

WgetHstsRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "apps/shell/wget/hsts",
    [
        ("datetime", "ts_created"),
        ("uri", "host"),
        ("boolean", "explicit_port"),
        ("boolean", "include_subdomains"),
        ("datetime", "max_age"),
        ("path", "source"),
    ],
)


class WgetPlugin(Plugin):
    """Wget shell plugin."""

    __namespace__ = "wget"

    def __init__(self, target: Target):
        super().__init__(target)
        self.artifacts = list(self._find_artifacts())

    def _find_artifacts(self) -> Iterator[tuple[UserDetails, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            if (hsts_file := user_details.home_path.joinpath(".wget-hsts")).exists():
                yield hsts_file, user_details

    def check_compatible(self) -> None:
        if not self.artifacts:
            raise UnsupportedPluginError("No .wget-hsts files found on target")

    @export(record=WgetHstsRecord)
    def hsts(self) -> Iterator[WgetHstsRecord]:
        """Yield domain entries found in wget HSTS files.

        When using the ``wget`` command-line utility, a file named ``.wget-hsts`` is created in the user's home
        directory by default. The ``.wget-hsts`` file records HTTP Strict Transport Security (HSTS) information for the
        websites visited by the user via ``wget``.

        Resources:
            - https://www.gnu.org/software/wget
            - https://gitlab.com/gnuwget/wget/-/blob/master/src/hsts.c
            - https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security

        Yields ``WgetHstsRecord`` records with the following fields:

        .. code-block:: text

            ts_created          (datetime):  When the host was first added to the HSTS file
            host                (uri):       The host that was accessed over TLS by wget
            explicit_port       (boolean):   If the TCP port for TLS should be checked
            include_subdomains  (boolean):   If subdomains are included in the HSTS check
            max_age             (datetime):  Time to live of the entry in the HSTS file
            source              (path):      Location of the .wget-hsts file
        """
        for hsts_file, user_details in self.artifacts:
            if not hsts_file.is_file():
                continue

            for line in hsts_file.open("rt").readlines():
                if not (line := line.strip()) or line.startswith("#"):
                    continue

                try:
                    host, port, subdomain_count, created, max_age = line.split("\t")

                except ValueError as e:
                    self.target.log.warning("Unexpected wget hsts line in file: %s", hsts_file)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield WgetHstsRecord(
                    ts_created=int(created),
                    host=host,
                    explicit_port=int(port),
                    include_subdomains=int(subdomain_count),
                    max_age=int(created) + int(max_age),
                    source=hsts_file,
                    _user=user_details.user,
                    _target=self.target,
                )
