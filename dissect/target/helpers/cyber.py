import fcntl
import random
import string
import sys
import termios
import time
from array import array
from contextlib import contextmanager, redirect_stdout
from enum import Enum
from io import StringIO
from typing import Iterator, Optional

# fmt: off
MASK_TABLE = [
    "!", '"', "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", "~", ".", "/", ":",
    ";", "<", "=", ">", "?", "[", "\\", "]", "_", "{", "}", "A", "B", "C", "D", "E", "F",
    "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W",
    "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
    "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4",
    "5", "6", "7", "8", "9", "Ç", "ü", "é", "â", "ä", "à", "å", "ç", "ê", "ë", "è", "ï",
    "î", "ì", "Ä", "Å", "É", "æ", "Æ", "ô", "ö", "ò", "û", "ù", "ÿ", "Ö", "Ü", "¢", "£",
    "¥", "ƒ", "á", "í", "ó", "ú", "ñ", "Ñ", "ª", "º", "¿", "¬", "½", "¼", "¡", "«", "»",
    "α", "ß", "Γ", "π", "Σ", "σ", "µ", "τ", "Φ", "Θ", "Ω", "δ", "φ", "ε", "±", "÷", "°",
    "·", "²", "¶", "⌐", "₧", "░", "▒", "▓", "│", "┤", "╡", "╢", "╖", "╕", "╣", "║", "╗",
    "╝", "╜", "╛", "┐", "└", "┴", "┬", "├", "─", "┼", "╞", "╟", "╚", "╔", "╩", "╦", "╠",
    "═", "╬", "╧", "╨", "╤", "╧", "╙", "╘", "╒", "╓", "╫", "╪", "┘", "┌", "█", "▄", "▌",
    "▐", "▀", "∞", "∩", "≡", "≥", "≤", "⌠", "⌡", "≈", "∙", "√", "ⁿ", "■",
]
# fmt: on

TYPE_EFFECT_SPEED = 4 / 1000
JUMBLE_SECONDS = 2
JUMBLE_LOOP_SPEED = 35
REVEAL_SECONDS = 5
REVEAL_LOOP_SPEED = 50


class Color(Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37


class CyberIO(StringIO):
    def __init__(self, color: Optional[Color] = None, mask_space: bool = False, run_at_end: bool = False):
        self._color = color
        self._mask_space = mask_space
        self._run_at_end = run_at_end
        super().__init__()

    def write(self, s: str) -> int:
        if self._run_at_end:
            super().write(s)
        else:
            nms(s, self._color, self._mask_space)
        return len(s)


@contextmanager
def cyber(color: Optional[Color] = Color.YELLOW, mask_space: bool = False, run_at_end: bool = False) -> None:
    stream = CyberIO(color, mask_space, run_at_end)
    with redirect_stdout(stream):
        yield

    if run_at_end:
        nms(stream.getvalue(), color, mask_space)


# https://github.com/bartobri/libnms
def nms(buf: str, color: Optional[Color] = None, mask_space: bool = False) -> None:
    if not buf or buf == "\n":
        sys.__stdout__.write(buf)
        return

    orig_row, orig_col = (0, 0)

    with _set_terminal():
        max_rows, max_cols = termios.tcgetwinsize(sys.__stdin__)

        orig_row, _ = _get_cursor_pos()

        _cursor_hide()
        _cursor_move(orig_row, orig_col)
        cur_row, cur_col = orig_row, orig_col

        # Prepare character information
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

            if end_ansi:
                reveal_time = random.randint(0, 100)
            else:
                reveal_time = random.randint(100, REVEAL_SECONDS * 1000)

            characters.append((char, random.choice(MASK_TABLE), reveal_time, has_ansi))

            if "\n" in char or "\r\n" in char:
                cur_col += 1

            if ("\n" in char or "\r\n" in char) or cur_col > max_cols:
                has_ansi = False
                cur_col = 0
                cur_row += 1
                if cur_row == max_rows + 1 and orig_row > 0:
                    orig_row -= 1
                    cur_row -= 1

        # Write initial mask
        for char, mask, _, _ in characters:
            if ("\n" in char or "\r\n" in char) or (not mask_space and char == " "):
                sys.__stdout__.write(char)
                continue

            sys.__stdout__.write(mask)

            sys.__stdout__.flush()
            time.sleep(TYPE_EFFECT_SPEED)

        _clear_input()
        time.sleep(1)

        for _ in range((JUMBLE_SECONDS * 1000) // JUMBLE_LOOP_SPEED):
            _cursor_move(orig_row, orig_col)

            for char, _, _, _ in characters:
                if ("\n" in char or "\r\n" in char) or (not mask_space and char == " "):
                    sys.__stdout__.write(char)
                    continue

                sys.__stdout__.write(random.choice(MASK_TABLE))

            sys.__stdout__.flush()
            time.sleep(JUMBLE_LOOP_SPEED / 1000)

        revealed = False

        while not revealed:
            _cursor_move(orig_row, orig_col)
            revealed = True

            for i, (char, mask, time_remaining, has_ansi) in enumerate(characters):
                if ("\n" in char or "\r\n" in char) or (not mask_space and char == " "):
                    sys.__stdout__.write(char)
                    continue

                if time_remaining > 0:
                    if time_remaining < 500:
                        if random.randint(0, 3) == 0:
                            mask = random.choice(MASK_TABLE)
                    else:
                        if random.randint(0, 10) == 0:
                            mask = random.choice(MASK_TABLE)

                    sys.__stdout__.write(mask)
                    time_remaining -= REVEAL_LOOP_SPEED

                    revealed = False
                    characters[i] = (char, mask, time_remaining, has_ansi)
                else:
                    if has_ansi:
                        sys.__stdout__.write(char)
                    else:
                        if color:
                            _bold()
                            _foreground_color(color.value)

                        sys.__stdout__.write(char)

                        if color:
                            _clear_attr()

            sys.__stdout__.flush()
            time.sleep(REVEAL_LOOP_SPEED / 1000)

        _clear_input()
        _cursor_show()


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


def _clear_input() -> None:
    i = array("i", [0])
    fcntl.ioctl(sys.__stdin__.buffer, termios.FIONREAD, i)
    sys.__stdin__.buffer.read(i[0])


def _isspace(s: str) -> bool:
    return s in ("\n", "\r")


def _cursor_home() -> None:
    sys.__stdout__.write("\033[H")
    sys.__stdout__.flush()


def _cursor_move(row: int, col: int) -> None:
    sys.__stdout__.write(f"\033[{row};{col}H")
    sys.__stdout__.flush()


def _beep() -> None:
    sys.__stdout__.write("\a")
    sys.__stdout__.flush()


def _bold() -> None:
    sys.__stdout__.write("\033[1m")
    sys.__stdout__.flush()


def _foreground_color(c: int) -> None:
    sys.__stdout__.write(f"\033[{c}m")
    sys.__stdout__.flush()


def _clear_attr() -> None:
    sys.__stdout__.write("\033[0m")
    sys.__stdout__.flush()


def _screen_save() -> None:
    sys.__stdout__.write("\033[?47h")
    sys.__stdout__.flush()


def _screen_restore() -> None:
    sys.__stdout__.write("\033[?47l")
    sys.__stdout__.flush()


def _cursor_save() -> None:
    sys.__stdout__.write("\033[s")
    sys.__stdout__.flush()


def _cursor_restore() -> None:
    sys.__stdout__.write("\033[u")
    sys.__stdout__.flush()


def _cursor_hide() -> None:
    sys.__stdout__.write("\033[?25l")
    sys.__stdout__.flush()


def _cursor_show() -> None:
    sys.__stdout__.write("\033[?25h")
    sys.__stdout__.flush()
