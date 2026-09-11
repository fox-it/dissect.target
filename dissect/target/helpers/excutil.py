from __future__ import annotations

import sys

try:
    _ExceptionGroup = BaseExceptionGroup
except NameError:  # Python 3.10 has no exception groups
    _ExceptionGroup = ()


def _is_stdlib(module: str) -> bool:
    """Return True if the module is part of the standard library."""
    return module != "__main__" and module.partition(".")[0] in sys.stdlib_module_names


def _location(exc: BaseException) -> str:
    """Return a string describing the location of the exception, e.g. " (dissect.target.target:851)"."""
    tb = exc.__traceback__
    if tb is None:
        return ""
    chosen = last = None
    while tb:
        if not _is_stdlib(tb.tb_frame.f_globals.get("__name__", "")):
            chosen = tb  # innermost non-stdlib frame so far
        last = tb
        tb = tb.tb_next
    tb = chosen or last  # all frames are stdlib: use the innermost one
    frame = tb.tb_frame
    module = frame.f_globals.get("__name__") or frame.f_code.co_filename
    return f" ({module}:{tb.tb_lineno})"


def summarize_exceptions(exc: BaseException, depth: int = 0) -> list[str]:
    """Summarize exceptions into a list of strings."""
    chain, seen = [], set()
    while isinstance(exc, BaseException) and id(exc) not in seen:
        seen.add(id(exc))
        chain.append(exc)
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)

    lines = []
    for e in reversed(chain):  # oldest first, same order Python prints them
        lines.append(f"{'  ' * depth}{type(e).__name__}: {e}{_location(e)}")
        if isinstance(e, _ExceptionGroup):
            for sub in e.exceptions:
                lines.extend(summarize_exceptions(sub, depth + 1))
    return lines
