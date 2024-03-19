import logging
from hashlib import md5
from pathlib import Path
from typing import Iterator, Optional

try:
    import yara

    HAS_YARA = True

except ImportError:
    HAS_YARA = False

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import InternalPlugin

log = logging.getLogger(__name__)

YaraMatchRecord = TargetRecordDescriptor(
    "filesystem/yara/match",
    [
        ("path", "path"),
        ("digest", "digest"),
        ("string", "rule"),
        ("string[]", "tags"),
        ("string", "namespace"),
    ],
)

MAX_SCAN_SIZE = 10 * 1024 * 1024


class YaraPlugin(InternalPlugin):
    """Plugin to scan files against a local YARA rules file."""

    def check_compatible(self) -> None:
        if not HAS_YARA:
            raise UnsupportedPluginError("Please install 'yara-python' to use the yara plugin.")

    def yara(
        self, rules: str | list[str | Path], path: str = "/", max_size: int = MAX_SCAN_SIZE, check_rules: bool = False
    ) -> Iterator[YaraMatchRecord]:
        """Scan files inside the target up to a given maximum size with YARA rule file(s)."""
        rules_path = rules

        if isinstance(rules, str):
            rules = rules.split(",")

        rules = process_rules(rules, check_rules)

        if not rules:
            self.target.log.error("No working rules found in %s.", rules_path)
            return set(())

        if hasattr(rules, "warnings") and (num_warns := len(rules.warnings)) > 0:
            log.warning("Yara generated %s warnings while compiling rules", num_warns)

        for _, _, files in self.target.fs.walk_ext(path):
            for file in files:
                try:
                    if file.stat().st_size > max_size:
                        continue

                    for match in rules.match(data=file.open().read()):
                        yield YaraMatchRecord(
                            path=file.path,
                            digest=file.hash(),
                            rule=match.rule,
                            tags=match.tags,
                            namespace=match.namespace,
                            _target=self.target,
                        )

                except FileNotFoundError:
                    continue
                except RuntimeWarning as e:
                    self.target.log.warning("Runtime warning while scanning file %s: %s", file.as_posix(), e)
                except Exception as e:
                    self.target.log.error("Exception scanning file %s", file)
                    self.target.log.debug("", exc_info=e)


def process_rules(rules_paths: list[str | Path], check_rules=False) -> Optional[yara.Rules]:
    """Generate Yara.Rules from the given path.

    Provide path to one (compiled) YARA file or directory containing YARA files.

    Args:
        rules: string path to file(s) or folder containing YARA files.
        check: attempt to compile every rule file before appending to rules.

    Returns: Compiled YARA rules.
    """
    files = {}
    rules = None

    for rules_path in rules_paths:
        if isinstance(rules_path, str):
            rules_path = Path(rules_path)

        if not rules_path.exists():
            log.warning("File %s does not exist!", rules_path.as_posix())
            continue

        if rules_path.is_dir():
            for file in rules_path.rglob("*"):
                if not file.is_file():
                    continue
                namespace = md5(file.as_posix().encode("utf-8")).digest().hex()
                files[namespace] = file.as_posix()
        else:
            namespace = md5(rules_path.as_posix().encode("utf-8")).digest().hex()
            files[namespace] = rules_path.as_posix()

    for namespace, file in dict(files).items():
        file = Path(file)

        with file.open("rb") as fh:
            magic = fh.read(4)

        if magic == b"YARA":
            if len(files) > 1:
                log.error("Providing multiple compiled YARA files is not supported. Did not add %s", file.as_posix())
                continue
            else:
                log.info("Adding single compiled YARA file %s", file.as_posix())
                rules = compile_yara(file)
                break

        elif check_rules and not compile_yara({namespace: file.as_posix()}):
            log.warning("File %s contains invalid rule(s)!", file.as_posix())
            files.pop(namespace)
            continue

    if files and not rules:
        rules = compile_yara(files)

    return rules


def compile_yara(files: dict[str, str] | Path) -> Optional[yara.Rules]:
    try:
        if isinstance(files, Path):
            return yara.load(files.as_posix())
        else:
            return yara.compile(filepaths=files)

    except (yara.SyntaxError, yara.WarningError, yara.Error) as e:
        log.debug("Rule file is invalid", exc_info=e)
        return None
