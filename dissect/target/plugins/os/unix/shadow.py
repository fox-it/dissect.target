from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

UnixShadowRecord = TargetRecordDescriptor(
    "unix/shadow",
    [
        ("string", "name"),
        ("string", "crypt"),
        ("string", "salt"),
        ("string", "hash"),
        ("string", "algorithm"),
        ("string", "crypt_param"),
        ("datetime", "last_change"),
        ("datetime", "min_age"),
        ("datetime", "max_age"),
        ("varint", "warning_period"),
        ("varint", "inactivity_period"),
        ("datetime", "expiration_date"),
        ("string", "unused_field"),
    ],
)


class ShadowPlugin(Plugin):
    """Unix shadow passwords plugin."""

    SHADOW_FILES = ("/etc/shadow", "/etc/shadow-")

    def check_compatible(self) -> None:
        if not self.target.fs.path("/etc/shadow").exists():
            raise UnsupportedPluginError("No shadow file found")

    @export(record=UnixShadowRecord)
    def passwords(self) -> Iterator[UnixShadowRecord]:
        """Yield shadow records from /etc/shadow files.

        Resources:
            - https://manpages.ubuntu.com/manpages/oracular/en/man5/passwd.5.html
            - https://linux.die.net/man/5/shadow
        """

        seen_hashes = set()

        for shadow_file in self.SHADOW_FILES:
            if (path := self.target.fs.path(shadow_file)).exists():
                for line in path.open("rt"):
                    line = line.strip()
                    if line == "" or line.startswith("#"):
                        continue

                    shent = dict(enumerate(line.split(":")))
                    crypt = extract_crypt_details(shent)

                    # do not return a shadow record if we have no hash
                    if crypt.get("hash") is None or crypt.get("hash") == "":
                        continue

                    # prevent duplicate user hashes
                    current_hash = (shent.get(0), crypt.get("hash"))
                    if current_hash in seen_hashes:
                        continue

                    seen_hashes.add(current_hash)

                    # improve readability
                    last_change = None
                    min_age = None
                    max_age = None
                    expiration_date = None

                    try:
                        last_change = int(shent.get(2)) if shent.get(2) else None
                    except ValueError as e:
                        self.target.log.warning(
                            "Unable to parse last_change shadow value in %s: %s ('%s')", shadow_file, e, shent.get(2)
                        )

                    try:
                        min_age = int(shent.get(3)) if shent.get(3) else None
                    except ValueError as e:
                        self.target.log.warning(
                            "Unable to parse last_change shadow value in %s: %s ('%s')", shadow_file, e, shent.get(3)
                        )

                    try:
                        max_age = int(shent.get(4)) if shent.get(4) else None
                    except ValueError as e:
                        self.target.log.warning(
                            "Unable to parse last_change shadow value in %s: %s ('%s')", shadow_file, e, shent.get(4)
                        )

                    try:
                        expiration_date = int(shent.get(7)) if shent.get(7) else None
                    except ValueError as e:
                        self.target.log.warning(
                            "Unable to parse last_change shadow value in %s: %s ('%s')", shadow_file, e, shent.get(7)
                        )

                    yield UnixShadowRecord(
                        name=shent.get(0),
                        crypt=shent.get(1),
                        algorithm=crypt.get("algo"),
                        crypt_param=crypt.get("param"),
                        salt=crypt.get("salt"),
                        hash=crypt.get("hash"),
                        last_change=epoch_days_to_datetime(last_change) if last_change else None,
                        min_age=epoch_days_to_datetime(last_change + min_age) if last_change and min_age else None,
                        max_age=epoch_days_to_datetime(last_change + max_age) if last_change and max_age else None,
                        warning_period=shent.get(5) if shent.get(5) else None,
                        inactivity_period=shent.get(6) if shent.get(6) else None,
                        expiration_date=epoch_days_to_datetime(expiration_date) if expiration_date else None,
                        unused_field=shent.get(8),
                        _target=self.target,
                    )


def extract_crypt_details(shent: dict) -> dict:
    """Extract different parts of a shadow entry such as
    the used crypto algorithm, any parameters, the used salt and hash.
    """

    crypt = {"algo": None, "param": None, "salt": None, "hash": None}
    c_parts = shent.get(1).split("$")

    algos = {
        "$0$": "des",
        "$1$": "md5",
        "$2$": "bcrypt",
        "$2a$": "bcrypt",
        "$2b$": "bcrypt",
        "$2x$": "bcrypt",
        "$2y$": "eksbcrypt",
        "$5$": "sha256",
        "$6$": "sha512",
        "$y$": "yescrypt",
        "$gy$": "gost-yescrypt",
        "$7$": "scrypt",
    }

    # yescrypt and scrypt are structured as: $id$param$salt$hash
    if len(c_parts) == 5:
        crypt = {
            "algo": "$" + c_parts[1] + "$",
            "param": c_parts[2],
            "salt": c_parts[3],
            "hash": c_parts[4],
        }

    # others are usually structured as: $id$salt$hash
    elif len(c_parts) == 4:
        crypt = {
            "algo": "$" + c_parts[1] + "$",
            "param": None,
            "salt": c_parts[2],
            "hash": c_parts[3],
        }

    # display a nicer alrogrithm name
    if crypt["algo"] in algos:
        crypt["algo"] = algos[crypt["algo"]]

    return crypt


def epoch_days_to_datetime(days: int) -> datetime:
    """Convert a number representing the days since 1 January 1970 to a datetime object."""
    if not isinstance(days, int):
        raise TypeError("days argument should be an integer")

    return datetime(1970, 1, 1, 0, 0, tzinfo=timezone.utc) + timedelta(days)
