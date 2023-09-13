from pathlib import Path

try:
    import yara
except ImportError:
    raise ImportError("Please install 'yara-python' to use 'target-query -f yara'.")

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

YaraMatchRecord = TargetRecordDescriptor(
    "filesystem/yara/match",
    [
        ("path", "path"),
        ("digest", "digest"),
        ("string", "rule"),
        ("string[]", "tags"),
    ],
)


class YaraPlugin(Plugin):
    """Plugin to scan files against a local YARA rules file."""

    DEFAULT_MAX_SIZE = 10 * 1024 * 1024

    def check_compatible(self) -> None:
        if not self.target.has_function("walkfs"):
            raise UnsupportedPluginError("No walkfs plugin found")

    @arg("--rule-files", "-r", type=Path, nargs="+", required=True, help="path to YARA rule file")
    @arg("--scan-path", default="/", help="path to recursively scan")
    @arg("--max-size", "-m", default=DEFAULT_MAX_SIZE, help="maximum file size in bytes to scan")
    @export(record=YaraMatchRecord)
    def yara(self, rule_files, scan_path="/", max_size=DEFAULT_MAX_SIZE):
        """Scan files up to a given maximum size with a local YARA rule file.

        Example:
            target-query <TARGET> -f yara --rule-file /path/to/yara_sigs.rule
        """

        rule_data = "\n".join([rule_file.read_text() for rule_file in rule_files])

        rules = yara.compile(source=rule_data)
        for entry, _ in self.target.walkfs_ext(scan_path):
            try:
                if not entry.is_file() or entry.stat().st_size > max_size:
                    continue

                for match in rules.match(data=entry.read_bytes()):
                    yield YaraMatchRecord(
                        path=entry,
                        digest=entry.get().hash(),
                        rule=match.rule,
                        tags=match.tags,
                        _target=self.target,
                    )
            except FileNotFoundError:
                continue
            except Exception:
                self.target.log.exception("Error scanning file: %s", entry)
