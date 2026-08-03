"""The necessary fnmatch internals for our pathlib implementation. Copied from Lib/fnmatch.py.

Update periodically.

Commit we're in sync with:
Hash:       add0ca9ea00ab02fd3a58d059e8370c2d0a1d32c
Date:       2025-05-03
Branch:     main (3.15)
URL:        https://github.com/python/cpython/commit/add0ca9ea00ab02fd3a58d059e8370c2d0a1d32c

Notes:
    - https://github.com/python/cpython/blob/main/Lib/fnmatch.py
"""

from __future__ import annotations

import functools
import re

_re_setops_sub = re.compile(r"([&~|])").sub
_re_escape = functools.lru_cache(maxsize=512)(re.escape)


def _translate(pat: str, star: str, question_mark: str) -> tuple[list[str], list[int]]:
    res = []
    add = res.append
    star_indices = []

    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        i = i + 1
        if c == "*":
            # store the position of the wildcard
            star_indices.append(len(res))
            add(star)
            # compress consecutive `*` into one
            while i < n and pat[i] == "*":
                i += 1
        elif c == "?":
            add(question_mark)
        elif c == "[":
            j = i
            if j < n and pat[j] == "!":
                j = j + 1
            if j < n and pat[j] == "]":
                j = j + 1
            while j < n and pat[j] != "]":
                j = j + 1
            if j >= n:
                add("\\[")
            else:
                stuff = pat[i:j]
                if "-" not in stuff:
                    stuff = stuff.replace("\\", r"\\")
                else:
                    chunks = []
                    k = i + 2 if pat[i] == "!" else i + 1
                    while True:
                        k = pat.find("-", k, j)
                        if k < 0:
                            break
                        chunks.append(pat[i:k])
                        i = k + 1
                        k = k + 3
                    chunk = pat[i:j]
                    if chunk:
                        chunks.append(chunk)
                    else:
                        chunks[-1] += "-"
                    # Remove empty ranges -- invalid in RE.
                    for k in range(len(chunks) - 1, 0, -1):
                        if chunks[k - 1][-1] > chunks[k][0]:
                            chunks[k - 1] = chunks[k - 1][:-1] + chunks[k][1:]
                            del chunks[k]
                    # Escape backslashes and hyphens for set difference (--).
                    # Hyphens that create ranges shouldn't be escaped.
                    stuff = "-".join(s.replace("\\", r"\\").replace("-", r"\-") for s in chunks)
                i = j + 1
                if not stuff:
                    # Empty range: never match.
                    add("(?!)")
                elif stuff == "!":
                    # Negated empty range: match any character.
                    add(".")
                else:
                    # Escape set operations (&&, ~~ and ||).
                    stuff = _re_setops_sub(r"\\\1", stuff)
                    if stuff[0] == "!":
                        stuff = "^" + stuff[1:]
                    elif stuff[0] in ("^", "["):
                        stuff = "\\" + stuff
                    add(f"[{stuff}]")
        else:
            add(_re_escape(c))
    assert i == n
    return res, star_indices
