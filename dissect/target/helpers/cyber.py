from __future__ import annotations

import os
import random
import string
import struct
import sys
import time
from array import array
from contextlib import contextmanager, redirect_stdout
from enum import Enum
from io import StringIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    import fcntl
    import termios

    CAN_CYBER = True
except ImportError:
    CAN_CYBER = False

# fmt: off
NMS_MASK_TABLE = [
    "!", '"', "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", "~", ".", "/", ":",
    ";", "<", "=", ">", "?", "[", "\\", "]", "_", "{", "}", "A", "B", "C", "D", "E", "F",
    "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W",
    "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
    "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4",
    "5", "6", "7", "8", "9", "Ç", "ü", "é", "â", "ä", "à", "å", "ç", "ê", "ë", "è", "ï",
    "î", "ì", "Ä", "Å", "É", "æ", "Æ", "ô", "ö", "ò", "û", "ù", "ÿ", "Ö", "Ü", "¢", "£",
    "¥", "ƒ", "á", "í", "ó", "ú", "ñ", "Ñ", "ª", "º", "¿", "¬", "½", "¼", "¡", "«", "»",
    "α", "ß", "Γ", "π", "Σ", "σ", "µ", "τ", "Φ", "Θ", "Ω", "δ", "φ", "ε", "±", "÷", "°",  # noqa: RUF001
    "·", "²", "¶", "⌐", "₧", "░", "▒", "▓", "│", "┤", "╡", "╢", "╖", "╕", "╣", "║", "╗",
    "╝", "╜", "╛", "┐", "└", "┴", "┬", "├", "─", "┼", "╞", "╟", "╚", "╔", "╩", "╦", "╠",
    "═", "╬", "╧", "╨", "╤", "╧", "╙", "╘", "╒", "╓", "╫", "╪", "┘", "┌", "█", "▄", "▌",
    "▐", "▀", "∞", "∩", "≡", "≥", "≤", "⌠", "⌡", "≈", "∙", "√", "ⁿ", "■",
]
# fmt: on

NMS_TYPE_EFFECT_SPEED = 4 / 1000
NMS_JUMBLE_SECONDS = 1
NMS_JUMBLE_LOOP_SPEED = 35
NMS_REVEAL_SECONDS = 2
NMS_REVEAL_LOOP_SPEED = 50

MATRIX_CHARS = list(map(chr, range(0x20, 0x7F)))

MATRIX_MAX_SPEED = 5
MATRIX_MAX_CASCADES = 600
MATRIX_MAX_COLS = 20
MATRIX_FRAME_DELAY = 0.03
MATRIX_REVEAL_SECONDS = 4


class Color(Enum):
    """Cyber colors."""

    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37


class CyberIO(StringIO):
    def __init__(self, color: Color | None = None, run_at_end: bool = False, **kwargs):
        self._color = color
        self._run_at_end = run_at_end
        self._kwargs = kwargs
        super().__init__()

    def write(self, s: str) -> int:
        if self._run_at_end:
            super().write(s)
        else:
            cyber_print(s, self._color, **self._kwargs)
        return len(s)


@contextmanager
def cyber(color: Color | None = Color.YELLOW, run_at_end: bool = False, **kwargs) -> Iterator[None]:
    stream = CyberIO(color, run_at_end, **kwargs)
    with redirect_stdout(stream):
        yield

    if run_at_end:
        cyber_print(stream.getvalue(), color, **kwargs)


def cyber_print(buf: str, color: Color | None = None, **kwargs) -> None:
    if not buf or buf == "\n":
        sys.__stdout__.write(buf)
        return

    if not CAN_CYBER:
        sys.__stdout__.write("you're not cybering hard enough\n")
        sys.__stdout__.write(buf)
        return

    if os.getenv("CYBER") == "💊":
        matrix(buf, color, **kwargs)
    else:
        nms(buf, color, **kwargs)


# https://github.com/bartobri/libnms
def nms(buf: str, color: Color | None = None, mask_space: bool = False, mask_indent: bool = True, **kwargs) -> None:
    orig_row, orig_col = (0, 0)
    with _set_terminal():
        max_rows, max_cols = _get_win_size()

        orig_row, _ = _get_cursor_pos()

        _cursor_hide()
        _cursor_move(orig_row, orig_col)

        characters, remaining, (orig_row, orig_col), _ = _get_character_info(
            buf, max_rows, max_cols, orig_row, orig_col
        )
        character_state = []

        try:
            is_indent = True
            # Write initial mask
            for char, has_ansi, end_ansi in characters:
                # Initialize the character state with a mask and reveal time
                reveal_time = random.randint(0, 100) if end_ansi else random.randint(100, NMS_REVEAL_SECONDS * 1000)

                mask = random.choice(NMS_MASK_TABLE)
                character_state.append((char, mask, reveal_time, has_ansi))

                if char != " ":
                    is_indent = False

                if (
                    ("\n" in char or "\r\n" in char)
                    or (not mask_space and char == " " and not is_indent)
                    or (not mask_indent and is_indent)
                ):
                    if "\n" in char:
                        is_indent = True
                    sys.__stdout__.write(char)
                    continue

                sys.__stdout__.write(mask)

                sys.__stdout__.flush()
                time.sleep(NMS_TYPE_EFFECT_SPEED)

            _clear_input()
            time.sleep(1)

            is_indent = True
            for _ in range((NMS_JUMBLE_SECONDS * 1000) // NMS_JUMBLE_LOOP_SPEED):
                _cursor_move(orig_row, orig_col)

                for char, _, _, _ in character_state:
                    if char != " ":
                        is_indent = False

                    if (
                        ("\n" in char or "\r\n" in char)
                        or (not mask_space and char == " ")
                        or (not mask_indent and is_indent)
                    ):
                        if "\n" in char:
                            is_indent = True
                        sys.__stdout__.write(char)
                        continue

                    sys.__stdout__.write(random.choice(NMS_MASK_TABLE))

                sys.__stdout__.flush()
                time.sleep(NMS_JUMBLE_LOOP_SPEED / 1000)

            revealed = False

            while not revealed:
                _cursor_move(orig_row, orig_col)
                revealed = True

                is_indent = True
                for i, (char, mask, time_remaining, has_ansi) in enumerate(character_state):
                    if char != " ":
                        is_indent = False

                    if (
                        ("\n" in char or "\r\n" in char)
                        or (not mask_space and char == " " and not is_indent)
                        or (not mask_indent and is_indent)
                    ):
                        if "\n" in char:
                            is_indent = True
                        sys.__stdout__.write(char)
                        continue

                    if time_remaining > 0:
                        if time_remaining < 500:
                            if random.randint(0, 3) == 0:
                                mask = random.choice(NMS_MASK_TABLE)
                        else:
                            if random.randint(0, 10) == 0:
                                mask = random.choice(NMS_MASK_TABLE)

                        sys.__stdout__.write(mask)
                        time_remaining -= NMS_REVEAL_LOOP_SPEED

                        revealed = False
                        character_state[i] = (char, mask, time_remaining, has_ansi)
                    else:
                        if has_ansi:
                            sys.__stdout__.write(char)
                        else:
                            if color:
                                _bold()
                                _foreground_color(color)

                            sys.__stdout__.write(char)

                            if color:
                                _clear_attr()

                sys.__stdout__.flush()
                time.sleep(NMS_REVEAL_LOOP_SPEED / 1000)

            _clear_input()
            _cursor_show()

            if remaining:
                _write_remaining(remaining, color)
        except KeyboardInterrupt:
            _clear_screen()
        finally:
            _clear_attr()
            _cursor_show()


# https://github.com/jsbueno/terminal_matrix
def matrix(buf: str, color: Color | None = None, **kwargs) -> None:
    orig_row, orig_col = (0, 0)
    with _set_terminal():
        max_rows, max_cols = _get_win_size()

        orig_row, _ = _get_cursor_pos()

        _cursor_hide()
        _clear_screen()
        _cursor_move(orig_row, orig_col)

        characters, remaining, (orig_row, orig_col), (end_row, _) = _get_character_info(
            buf, max_rows, max_cols, orig_row, orig_col
        )
        reveal_cols = [[" " for _ in range(max_rows + 1)] for _ in range(max_cols)]

        cur_ansi = ""
        row = column = 0
        for char, has_ansi, end_ansi in characters:
            if has_ansi:
                if end_ansi:
                    cur_ansi += char[:-5][:-4]
                else:
                    cur_ansi += char[:-1]
            elif color:
                cur_ansi = f"\033[1m\033[0;{color.value}m"

            if cur_ansi:
                char = cur_ansi + char + "\033[0m"
                if end_ansi:
                    cur_ansi = ""

            if "\n" in char or "\r\n" in char:
                char = " " + char

            reveal_cols[column][row] = char

            if "\n" in char or "\r\n" in char or column == max_cols:
                row += 1
                column = 0
            else:
                column += 1

        time_remaining = MATRIX_REVEAL_SECONDS

        try:
            cascading = set()
            remaining_columns = set(range(1, max_cols))
            occupied_columns = set()

            while True:
                if time_remaining > 0:
                    while True:
                        if random.randrange(MATRIX_MAX_CASCADES + 1) > len(cascading):
                            start_col = random.randrange(1, max_cols)
                            for i in range(random.randrange(MATRIX_MAX_COLS)):
                                col = (start_col + i) % (max_cols + 1)
                                if col != 0 and col not in occupied_columns:
                                    cascading.add(_cascade(col, max_rows + 1, reveal_cols[col - 1]))
                                    occupied_columns.add(col)
                                    remaining_columns.discard(col)
                        break
                elif remaining_columns:
                    while remaining_columns:
                        col = remaining_columns.pop()
                        cascading.add(_cascade(col, max_rows, reveal_cols[col - 1]))

                stopped = set()
                for c in cascading:
                    try:
                        next(c)
                    except StopIteration:  # noqa: PERF203
                        stopped.add(c)

                sys.__stdout__.flush()

                cascading.difference_update(stopped)
                time_remaining -= MATRIX_FRAME_DELAY
                time.sleep(MATRIX_FRAME_DELAY)

                if not cascading:
                    break

            _cursor_move(end_row - orig_row + 1, 0)
            if remaining:
                _write_remaining(remaining, color)
        except KeyboardInterrupt:
            _clear_screen()
        finally:
            _clear_attr()
            _cursor_show()


def _cascade(col: int, max_rows: int, reveal_row: list[str]) -> Iterator:
    speed = random.randrange(1, MATRIX_MAX_SPEED)
    erase_speed = random.randrange(1, MATRIX_MAX_SPEED)

    if speed < erase_speed:
        speed, erase_speed = erase_speed, speed

    row = counter = erase_counter = 0
    old_row = erase_row = -1
    erasing = False
    bright = True

    limit = max(0, max_rows - (random.paretovariate(1.16) - 1) * (max_rows // 2))

    while True:
        counter, row = _update_row(speed, counter, row)
        if random.randrange(10 * speed) < 1:
            bright = False

        if row > 1 and row <= limit and old_row != row:
            _print_at(random.choice(MATRIX_CHARS), row - 1, col, Color.GREEN, bright)

        if row < limit:
            _print_at(random.choice(MATRIX_CHARS), row, col, Color.WHITE, bright)

        if not erasing:
            erasing = random.randrange(row + 1) > (max_rows / 2)
            erase_row = 0
        else:
            erase_counter, erase_row = _update_row(erase_speed, erase_counter, erase_row)

            for i in range(1, erase_row):
                _print_at(reveal_row[i - 1], i, col)

        yield None

        if erase_row >= max_rows:
            for i in range(1, max_rows):
                _print_at(reveal_row[i - 1], i, col)
            break


def _update_row(speed: int, counter: int, row: int) -> tuple[int, int]:
    counter += 1
    if counter >= speed:
        row += 1
        counter = 0
    return counter, row


def _get_character_info(
    buf: str, max_rows: int, max_cols: int, orig_row: int, orig_col: int
) -> tuple[list[tuple[str, bool, bool]], str, tuple[int, int], tuple[int, int]]:
    cur_row, cur_col = orig_row, orig_col

    characters = []
    has_ansi = False
    end_ansi = False

    i = 0
    while i < len(buf):
        if cur_row - orig_row >= max_rows - 1:
            break

        if end_ansi:
            has_ansi = False
            end_ansi = False

        char = buf[i]
        i += 1

        if char == "\033":
            has_ansi = True

            while i < len(buf):
                char += buf[i]
                i += 1

                if char[-1] in string.ascii_letters and i < len(buf):
                    # First letter is the end of the ANSI code, read one more
                    char += buf[i]
                    i += 1

                    if char[-1] != "\033":
                        # The real end, now we have a char with ANSI codes prepended to it
                        break

        if (ansi_reset := buf[i : i + 4]) == "\033[0m":
            char += ansi_reset
            i += 4
            end_ansi = True

        if char == "\r" and i < len(buf) and buf[i] == "\n":
            char += buf[i]
            i += 1

        characters.append((char, has_ansi, end_ansi))

        if ("\n" in char or "\r\n" in char) or cur_col > max_cols:
            has_ansi = False
            cur_col = 0
            cur_row += 1
            if cur_row == max_rows + 1 and orig_row > 0:
                orig_row -= 1
                cur_row -= 1

    remaining = buf[i:]

    return characters, remaining, (orig_row, orig_col), (cur_row, cur_col)


def _write_remaining(remaining: str, color: Color | None) -> None:
    time.sleep(0.5)

    if color and "\033" not in remaining:
        _bold()
        _foreground_color(color)

    sys.__stdout__.write(remaining)

    if color and "\033" not in remaining:
        _clear_attr()


@contextmanager
def _set_terminal() -> Iterator[None]:
    attr = termios.tcgetattr(sys.__stdin__)

    new = attr[:]
    new[3] &= ~termios.ICANON & ~termios.ECHO

    termios.tcsetattr(sys.__stdin__, termios.TCSAFLUSH, new)

    try:
        yield
    finally:
        termios.tcsetattr(sys.__stdin__, termios.TCSANOW, attr)


def _get_win_size() -> tuple[int, int]:
    packed = fcntl.ioctl(sys.__stdin__.buffer, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
    rows, cols, _, _ = struct.unpack("HHHH", packed)
    return rows, cols


def _get_cursor_pos() -> int:
    sys.__stdout__.write("\033[6n")
    sys.__stdout__.flush()

    buf = ""
    while (c := sys.__stdin__.read(1)) != "R":
        if c in ("\033", "["):
            continue

        buf += c

    row, col = map(int, buf.split(";"))

    return row, col


def _print_at(s: str, row: int, col: int, color: Color | None = None, bright: bool = False) -> None:
    _cursor_move(row, col)
    if color:
        _foreground_color(color, bright)
    sys.__stdout__.write(s)
    if color:
        _clear_attr()


def _clear_input() -> None:
    i = array("i", [0])
    fcntl.ioctl(sys.__stdin__.buffer, termios.FIONREAD, i)
    sys.__stdin__.buffer.read(i[0])


def _cursor_move(row: int, col: int) -> None:
    sys.__stdout__.write(f"\033[{row};{col}H")
    sys.__stdout__.flush()


def _bold() -> None:
    sys.__stdout__.write("\033[1m")
    sys.__stdout__.flush()


def _foreground_color(c: Color, bright: bool = False) -> None:
    sys.__stdout__.write(f"\033[{'1' if bright else '0'};{c.value}m")
    sys.__stdout__.flush()


def _clear_attr() -> None:
    sys.__stdout__.write("\033[0m")
    sys.__stdout__.flush()


def _clear_screen() -> None:
    sys.__stdout__.write("\033[2J")
    sys.__stdout__.flush()


def _cursor_hide() -> None:
    sys.__stdout__.write("\033[?25l")
    sys.__stdout__.flush()


def _cursor_show() -> None:
    sys.__stdout__.write("\033[?25h")
    sys.__stdout__.flush()
