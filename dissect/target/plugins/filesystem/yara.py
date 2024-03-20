import logging
from hashlib import md5
from io import BytesIO
from pathlib import Path
from typing import Iterator, Optional

from dissect.target.helpers import hashutil

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

DEFAULT_MAX_SCAN_SIZE = 10 * 1024 * 1024


class YaraPlugin(InternalPlugin):
    """Plugin to scan files against a local YARA rules file."""

    def check_compatible(self) -> None:
        if not HAS_YARA:
            raise UnsupportedPluginError("Please install 'yara-python' to use the yara plugin.")

    def yara(
        self,
        rules: list[str | Path],
        path: str = "/",
        max_size: int = DEFAULT_MAX_SCAN_SIZE,
        check: bool = False,
    ) -> Iterator[YaraMatchRecord]:
        """Scan files inside the target up to a given maximum size with YARA rule file(s).

        Args:
            rules: ``list`` of strings or ``Path`` objects pointing to rule files to use.
            path: ``string`` of absolute target path to scan.
            max_size: Files larger than this size will not be scanned.
            check: Check if provided rules are valid, only compiles valid rules.

        Returns:
            Iterator yields ``YaraMatchRecord``.
        """

        compiled_rules = process_rules(rules, check)

        if not rules:
            self.target.log.error("No working rules found in '%s'", ",".join(rules))
            return

        if hasattr(compiled_rules, "warnings") and (num_warns := len(compiled_rules.warnings)) > 0:
            self.target.log.warning("Yara generated %s warnings while compiling rules", num_warns)
            for warning in compiled_rules.warnings:
                self.target.log.debug(warning)

        self.target.log.warning("Will not scan files larger than %s MB", max_size // 1024 // 1024)

        for _, _, files in self.target.fs.walk_ext(path):
            for file in files:
                try:
                    if file_size := file.stat().st_size > max_size:
                        self.target.log.debug(
                            "Skipping file '%s' as it is larger than %s bytes (size is %s)", file, file_size, max_size
                        )
                        continue

                    file_content = file.open().read()
                    for match in compiled_rules.match(data=file_content):
                        yield YaraMatchRecord(
                            path=self.target.fs.path(file.path),
                            digest=hashutil.common(BytesIO(file_content)),
                            rule=match.rule,
                            tags=match.tags,
                            namespace=match.namespace,
                            _target=self.target,
                        )

                except FileNotFoundError:
                    continue
                except RuntimeWarning as e:
                    self.target.log.warning("Runtime warning while scanning file '%s': %s", file, e)
                except Exception as e:
                    self.target.log.error("Exception scanning file '%s'", file)
                    self.target.log.debug("", exc_info=e)


def process_rules(paths: list[str | Path], check: bool = False) -> Optional[yara.Rules]:
    """Generate compiled YARA rules from the given path(s).

    Provide path to one (compiled) YARA file or directory containing YARA files.

    Args:
        paths: Path to file(s) or folder(s) containing YARA files.
        check: Attempt to compile every rule file before appending to rules.

    Returns:
        Compiled YARA rules or None.
    """
    files = set()
    compiled_rules = None

    for rules_path in paths:
        if isinstance(rules_path, str):
            rules_path = Path(rules_path)

        if not rules_path.exists():
            log.warning("File %s does not exist!", rules_path)
            continue

        if rules_path.is_dir():
            for file in rules_path.rglob("*"):
                if not file.is_file():
                    continue
                files.add(file)
        else:
            files.add(rules_path)

    for file in set(files):
        with file.open("rb") as fh:
            magic = fh.read(4)

        if magic == b"YARA":
            if len(files) > 1:
                log.error("Providing multiple compiled YARA files is not supported. Did not add %s", file)
                continue
            else:
                log.info("Adding single compiled YARA file %s", file)
                compiled_rules = compile_yara(file, is_compiled=True)
                break

        elif check and not compile_yara({"check_namespace": file}):
            log.warning("File %s contains invalid rule(s)!", file)
            files.remove(file)
            continue

    if files and not compiled_rules:
        compiled_rules = compile_yara({md5(file.as_posix().encode("utf-8")).digest().hex(): file for file in files})

    return compiled_rules


def compile_yara(files: dict[str, Path] | Path, is_compiled: bool = False) -> Optional[yara.Rules]:
    try:
        if is_compiled and isinstance(files, Path):
            return yara.load(files.as_posix())
        else:
            return yara.compile(filepaths={ns: Path(path).as_posix() for ns, path in files.items()})
    except (yara.SyntaxError, yara.WarningError, yara.Error) as e:
        log.debug("Rule file is invalid: %s", e)
        return None
