from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ShellHistoryRecord = TargetRecordDescriptor(
    "macos/shellhistory/entries",
    [
        ("datetime", "ts"),
        ("string", "command"),
        ("varint", "duration"),
        ("string", "shell"),
        ("path", "source"),
    ],
)

EPOCH_ZERO = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ShellHistoryPlugin(Plugin):
    """Plugin to parse macOS shell history files.

    Parses zsh and bash history from:
    - ~/.zsh_history (may contain extended format: `: timestamp:duration;command`)
    - ~/.bash_history (plain commands)
    - ~/.zsh_sessions/*.history* (zsh session history files)
    """

    __namespace__ = "shellhistory"

    HISTORY_GLOBS = [
        "Users/*/.zsh_history",
        "Users/*/%2Ezsh_history",
        "Users/*/.bash_history",
        "Users/*/%2Ebash_history",
        "Users/*/.zsh_sessions/*.history*",
        "Users/*/%2Ezsh_sessions/*.history*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        root = self.target.fs.path("/")
        for pattern in self.HISTORY_GLOBS:
            self._paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No shell history files found")

    def _detect_shell(self, path):
        name = str(path)
        if "bash" in name:
            return "bash"
        return "zsh"

    @export(record=ShellHistoryRecord)
    def entries(self) -> Iterator[ShellHistoryRecord]:
        """Parse shell history files (zsh extended format and plain commands)."""
        for path in self._paths:
            try:
                with path.open("r", errors="replace") as fh:
                    content = fh.read()
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", path, e)
                continue

            shell = self._detect_shell(path)

            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue

                try:
                    # zsh extended format: `: timestamp:duration;command`
                    if line.startswith(": ") and ";" in line:
                        meta, _, command = line.partition(";")
                        parts = meta.split(":")
                        if len(parts) >= 3:
                            try:
                                ts_val = int(parts[1].strip())
                                duration = int(parts[2].strip())
                                ts = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                            except (ValueError, OSError):
                                ts = EPOCH_ZERO
                                duration = 0
                                command = line
                        else:
                            ts = EPOCH_ZERO
                            duration = 0
                            command = line
                    else:
                        # Plain command (bash or plain zsh)
                        ts = EPOCH_ZERO
                        duration = 0
                        command = line

                    if command.strip():
                        yield ShellHistoryRecord(
                            ts=ts,
                            command=command.strip(),
                            duration=duration,
                            shell=shell,
                            source=path,
                            _target=self.target,
                        )
                except Exception as e:
                    self.target.log.warning("Error parsing line in %s: %s", path, e)
