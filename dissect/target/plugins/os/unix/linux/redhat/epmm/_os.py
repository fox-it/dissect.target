from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import ConfigurationParsingError
from dissect.target.helpers import configutil
from dissect.target.helpers.record import TargetRecordDescriptor, UnixUserRecord
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.linux.redhat._os import RedHatPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


EPMMUserRecord = TargetRecordDescriptor(
    "epmm/user",
    [
        ("string", "name"),
        ("string", "password"),
        ("string", "gecos"),
        ("string[]", "groups"),
        ("string[]", "roles"),
        ("path", "source"),
    ],
)


class IvantiEpmmPlugin(RedHatPlugin):
    """Ivanti Endpoint Protect Mobile Manager (EPMM) (previously Mobile Iron Core) OS plugin."""

    DETECT_PATHS = (
        "/mi/release",
        "/mi/config-system",
        "/var/log/mi.log",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.config = self._parse_config()

    def _parse_config(self) -> dict:
        """Mobile Iron stores configuration data in XML and XSL files in the ``/mi/config-system`` directory.

        Currently we do not parse /mi/tomcat-properties/configurationService.properties -> configuration.directory.
        """
        config = {}
        for file in ("system", "identity", "antivirus", "debug", "filesystem", "ipsec"):
            if (path := self.target.fs.path(f"/mi/config-system/startup_config/{file}config.xml")).is_file():
                try:
                    config[file] = configutil.parse(
                        path, hint="xml", namespace=rf"{{http://xsdobjects.mi.com/{file}conf}}"
                    )
                except ConfigurationParsingError as e:
                    self.target.log.warning("Unable to parse file %s: %s", path, e)
        return config

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            for path in cls.DETECT_PATHS:
                if fs.exists(path):
                    return fs
        return None

    @export(property=True)
    def hostname(self) -> str:
        """Return the configured hostname."""
        try:
            return self.config["system"]["configuration"]["system"]["hostname"]["hname"]
        except KeyError:
            return super().hostname

    @export(property=True)
    def domain(self) -> str:
        """Return the configured (search) domain."""
        try:
            return self.config["system"]["configuration"]["system"]["dnsname"]["domainname"]
        except KeyError:
            return super().domain

    @export(property=True)
    def ips(self) -> list[str]:
        """Return the configured IP address(es)."""
        try:
            # Parse all configured interfaces
            interfaces = self.config["system"]["configuration"]["system"]["interface"]
            ips = []
            for ip_type in ("ipaddress", "ip6address"):
                ips.extend([ip for iface in interfaces if (ip := iface.get(ip_type)) not in ("0.0.0.0", None)])
        except KeyError:
            pass

        # Fall back to generic RedHat/Linux parsing if no ips were found
        return ips or super().ips

    @export(property=True)
    def dns(self) -> list[str] | None:
        """Return the configured DNS servers."""
        try:
            return [item.get("ipaddress") for item in self.config["system"]["configuration"]["system"]["dns"]]
        except KeyError:
            pass

    @export(property=True)
    def gateway(self) -> list[str] | None:
        """Return list of configured gateway ip addresses."""
        routes = self.config["system"]["configuration"]["system"]["route"]
        if not isinstance(routes, list):
            routes = [routes]
        try:
            return [r.get("gateway") for r in routes]
        except KeyError:
            pass

    @export(property=True)
    def version(self) -> str:
        """Return the Ivanti EPMM build version string."""
        mi_version = (
            rel.read_text().strip() if (rel := self.target.fs.path("/mi/release")).is_file() else "unknown build"
        )
        sys_version = super().version or "unknown Linux version"
        return f"Ivanti EPMM {mi_version} ({sys_version})"

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[EPMMUserRecord | UnixUserRecord]:
        """Yield Ivanti EPMM user records from identityconfig.xml and unix user records from /etc/passwd."""
        # Yield unix-like users from /etc/passwd.
        yield from super().users()

        # Yield EPMM configured identities.
        try:
            identity = self.config["identity"]["configuration"]["identity"]
            users = identity["user"]
            roles = identity["roles"]
        except KeyError:
            pass

        if not isinstance(users, list):
            users = [users]

        if not isinstance(roles, list):
            roles = [roles]

        for user in users:
            full_name = f"{user.get('firstname')} {user.get('lastname')}".strip()
            yield EPMMUserRecord(
                name=user.get("principal"),
                password=user.get("passwordHashSHA512"),
                gecos=f"{full_name},,,,{user.get('email')}",
                groups=[user.get("group")],
                roles=next(r["role"] for r in roles if r["principal"] == user["principal"]),
                source="/mi/config-system/startup_config/identityconfig.xml",
                _target=self.target,
            )
