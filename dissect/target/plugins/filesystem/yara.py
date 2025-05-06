from __future__ import annotations

import hashlib
import logging
from io import BytesIO
from pathlib import Path

from dissect.target.helpers import hashutil

try:
    import yara

    HAS_YARA = True

except ImportError:
    HAS_YARA = False

from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

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


class YaraPlugin(Plugin):
    """Plugin to scan files against a local YARA rules file."""

    def check_compatible(self) -> None:
        if not HAS_YARA:
            raise UnsupportedPluginError("Please install 'yara-python' to use the yara plugin.")

    @arg("-r", "--rules", required=True, nargs="*", help="path(s) to YARA rule file(s) or folder(s)")
    @arg("-p", "--path", default="/", help="path on target(s) to recursively scan")
    @arg("-m", "--max-size", type=int, default=DEFAULT_MAX_SCAN_SIZE, help="maximum file size in bytes to scan")
    @arg("-c", "--check", action="store_true", help="check if every YARA rule is valid")
    @export(record=YaraMatchRecord)
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
            self.target.log.warning("YARA generated %s warnings while compiling rules", num_warns)
            for warning in compiled_rules.warnings:
                self.target.log.info(warning)

        self.target.log.warning("Will not scan files larger than %s MB", max_size // 1024 // 1024)

        for _, _, files in self.target.fs.walk_ext(path):
            for file in files:
                try:
                    if (file_size := file.stat().st_size) > max_size:
                        self.target.log.info("Not scanning file of %s MB: '%s'", (file_size // 1024 // 1024), file)
                        continue

                    buf = file.open().read()
                    for match in compiled_rules.match(data=buf):
                        yield YaraMatchRecord(
                            path=self.target.fs.path(file.path),
                            digest=hashutil.common(BytesIO(buf)),
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
                    self.target.log.error("Exception scanning file '%s'", file)  # noqa: TRY400
                    self.target.log.debug("", exc_info=e)


def process_rules(paths: list[str | Path], check: bool = False) -> yara.Rules | None:
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
            log.info("Adding single compiled YARA file %s", file)
            compiled_rules = compile_yara(file, is_compiled=True)
            break

        if check and not is_valid_yara({"check_namespace": file}):
            log.warning("File %s contains invalid rule(s)!", file)
            files.remove(file)
            continue

    if files and not compiled_rules:
        try:
            compiled_rules = compile_yara({hashlib.md5(file.as_posix().encode()).hexdigest(): file for file in files})
        except yara.Error as e:
            log.error("Failed to compile YARA file(s): %s", e)  # noqa: TRY400

    return compiled_rules


def compile_yara(files: dict[str, Path] | Path, is_compiled: bool = False) -> yara.Rules | None:
    """Compile or load the given YARA file(s) to rules."""
    if is_compiled and isinstance(files, Path):
        return yara.load(files.as_posix())
    return yara.compile(filepaths={ns: Path(path).as_posix() for ns, path in files.items()})


def is_valid_yara(files: dict[str, Path] | Path, is_compiled: bool = False) -> bool:
    """Determine if the given YARA file(s) compile without errors or warnings."""
    try:
        compile_yara(files, is_compiled)
    except (yara.SyntaxError, yara.WarningError, yara.Error) as e:
        log.debug("Rule file(s) '%s' invalid: %s", files, e)
        return False
    else:
        return True
