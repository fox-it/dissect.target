from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

UnixShadowRecord = TargetRecordDescriptor(
    "unix/shadow",
    [
        ("string", "name"),
        ("string", "crypt"),
        ("string", "salt"),
        ("string", "hash"),
        ("string", "algorithm"),
        ("string", "crypt_param"),
        ("string", "last_change"),
        ("varint", "min_age"),
        ("varint", "max_age"),
        ("varint", "warning_period"),
        ("string", "inactivity_period"),
        ("string", "expiration_date"),
        ("string", "unused_field"),
    ],
)


class ShadowPlugin(Plugin):
    """Unix shadow passwords plugin."""

    def check_compatible(self) -> None:
        if not self.target.fs.path("/etc/shadow").exists():
            raise UnsupportedPluginError("No shadow file found")

    SHADOW_FILES = ["/etc/shadow", "/etc/shadow-"]

    @export(record=UnixShadowRecord)
    def passwords(self) -> Iterator[UnixShadowRecord]:
        """Yield shadow records from /etc/shadow files.

        Resources:
            - https://manpages.ubuntu.com/manpages/oracular/en/man5/passwd.5.html
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

                    yield UnixShadowRecord(
                        name=shent.get(0),
                        crypt=shent.get(1),
                        algorithm=crypt.get("algo"),
                        crypt_param=crypt.get("param"),
                        salt=crypt.get("salt"),
                        hash=crypt.get("hash"),
                        last_change=shent.get(2),
                        min_age=shent.get(3),
                        max_age=shent.get(4),
                        warning_period=shent.get(5),
                        inactivity_period=shent.get(6),
                        expiration_date=shent.get(7),
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
