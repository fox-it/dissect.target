from __future__ import annotations

import logging
import sys
from typing import Any

TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")

# For some reason, 3.10 and earlier need stacklevel=3
_STACK_LEVEL = 2 if sys.version_info >= (3, 11) else 3


class TraceLogger(logging.Logger):
    def trace(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(TRACE_LEVEL):
            # Set stacklevel so that logging shows the correct caller info
            kwargs.setdefault("stacklevel", _STACK_LEVEL)
            self._log(TRACE_LEVEL, msg, args, **kwargs)


logging.setLoggerClass(TraceLogger)


def get_logger(name: str | None = None) -> TraceLogger:
    """Get a logger with ``TRACE`` support."""
    return logging.getLogger(name)


class TargetLogAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        return f"{self.extra['target']}: {msg}", kwargs

    def trace(self, msg: Any, *args, **kwargs) -> None:
        """Delegate a trace call to the underlying logger."""
        # Set stacklevel so that logging shows the correct caller info
        self.log(TRACE_LEVEL, msg, *args, stacklevel=_STACK_LEVEL, **kwargs)
