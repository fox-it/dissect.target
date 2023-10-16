import random
import sys
import termios
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from dissect.target import Target
from dissect.target.loader import Loader
from dissect.target.loader import open as loader_open

# fmt: off
MASK_TABLE = [
    "⠀", "⠁", "⠂", "⠃", "⠄", "⠅", "⠆", "⠇", "⠈", "⠉", "⠊", "⠋", "⠌", "⠍", "⠎", "⠏",
    "⠐", "⠑", "⠒", "⠓", "⠔", "⠕", "⠖", "⠗", "⠘", "⠙", "⠚", "⠛", "⠜", "⠝", "⠞", "⠟",
    "⠠", "⠡", "⠢", "⠣", "⠤", "⠥", "⠦", "⠧", "⠨", "⠩", "⠪", "⠫", "⠬", "⠭", "⠮", "⠯",
    "⠰", "⠱", "⠲", "⠳", "⠴", "⠵", "⠶", "⠷", "⠸", "⠹", "⠺", "⠻", "⠼", "⠽", "⠾", "⠿",
    "⡀", "⡁", "⡂", "⡃", "⡄", "⡅", "⡆", "⡇", "⡈", "⡉", "⡊", "⡋", "⡌", "⡍", "⡎", "⡏",
    "⡐", "⡑", "⡒", "⡓", "⡔", "⡕", "⡖", "⡗", "⡘", "⡙", "⡚", "⡛", "⡜", "⡝", "⡞", "⡟",
    "⡠", "⡡", "⡢", "⡣", "⡤", "⡥", "⡦", "⡧", "⡨", "⡩", "⡪", "⡫", "⡬", "⡭", "⡮", "⡯",
    "⡰", "⡱", "⡲", "⡳", "⡴", "⡵", "⡶", "⡷", "⡸", "⡹", "⡺", "⡻", "⡼", "⡽", "⡾", "⡿",
    "⢀", "⢁", "⢂", "⢃", "⢄", "⢅", "⢆", "⢇", "⢈", "⢉", "⢊", "⢋", "⢌", "⢍", "⢎", "⢏",
    "⢐", "⢑", "⢒", "⢓", "⢔", "⢕", "⢖", "⢗", "⢘", "⢙", "⢚", "⢛", "⢜", "⢝", "⢞", "⢟",
    "⢠", "⢡", "⢢", "⢣", "⢤", "⢥", "⢦", "⢧", "⢨", "⢩", "⢪", "⢫", "⢬", "⢭", "⢮", "⢯",
    "⢰", "⢱", "⢲", "⢳", "⢴", "⢵", "⢶", "⢷", "⢸", "⢹", "⢺", "⢻", "⢼", "⢽", "⢾", "⢿",
    "⣀", "⣁", "⣂", "⣃", "⣄", "⣅", "⣆", "⣇", "⣈", "⣉", "⣊", "⣋", "⣌", "⣍", "⣎", "⣏",
    "⣐", "⣑", "⣒", "⣓", "⣔", "⣕", "⣖", "⣗", "⣘", "⣙", "⣚", "⣛", "⣜", "⣝", "⣞", "⣟",
    "⣠", "⣡", "⣢", "⣣", "⣤", "⣥", "⣦", "⣧", "⣨", "⣩", "⣪", "⣫", "⣬", "⣭", "⣮", "⣯",
    "⣰", "⣱", "⣲", "⣳", "⣴", "⣵", "⣶", "⣷", "⣸", "⣹", "⣺", "⣻", "⣼", "⣽", "⣾", "⣿",
]
# fmt: on

TYPE_EFFECT_SPEED = 4
JUMBLE_SECONDS = 2
JUMBLE_LOOP_SPEED = 35
REVEAL_LOOP_SPEED = 50


HEADER = r"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃      _______     ______  ______ _____      ┃
┃     / ____\ \   / /  _ \|  ____|  __ \     ┃
┃    | |     \ \_/ /| |_) | |__  | |__) |    ┃
┃    | |      \   / |  _ <|  __| |  _  /     ┃
┃    | |____   | |  | |_) | |____| | \ \     ┃
┃     \_____|  |_|  |____/|______|_|  \_\    ┃
┃                                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

"""


class CyberLoader(Loader):
    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self._real = loader_open(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        nms(HEADER)
        return self._real.map(target)


# https://github.com/bartobri/libnms
def nms(buf: str) -> None:
    orig_row, orig_col = (0, 0)
    with _set_terminal():
        max_rows, max_cols = termios.tcgetwinsize(sys.stdin)

        orig_row = _get_cursor_row()
        _cursor_move(orig_row, orig_col)
        cur_row, cur_col = orig_row, orig_col

        characters = []
        for char in buf:
            if cur_row - orig_row >= max_rows - 1:
                break

            characters.append((char, random.choice(MASK_TABLE), random.randint(0, 5000)))

            if char != "\n":
                cur_col += 1

            if char == "\n" or cur_col > max_cols:
                cur_col = 0
                cur_row += 1
                if cur_row == max_rows + 1 and orig_row > 0:
                    orig_row -= 1
                    cur_row -= 1

        for char, mask, _ in characters:
            if _isspace(char):
                sys.__stdout__.write(char)
                continue

            sys.__stdout__.write(mask)

            sys.__stdout__.flush()
            time.sleep(TYPE_EFFECT_SPEED / 1000)

        termios.tcdrain(sys.stdin)

        time.sleep(1)

        for _ in range((JUMBLE_SECONDS * 1000) // JUMBLE_LOOP_SPEED):
            _cursor_move(orig_row, orig_col)

            for char, _, _ in characters:
                if _isspace(char):
                    sys.__stdout__.write(char)
                    continue

                sys.__stdout__.write(random.choice(MASK_TABLE))

            sys.__stdout__.flush()
            time.sleep(JUMBLE_LOOP_SPEED / 1000)

        revealed = False

        while not revealed:
            _cursor_move(orig_row, orig_col)
            revealed = True

            for i, (char, mask, time_remaining) in enumerate(characters):
                if _isspace(char):
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

                    revealed = 0
                    characters[i] = (char, mask, time_remaining)
                else:
                    # _bold()
                    _foreground_color(3)
                    sys.__stdout__.write(char)
                    _clear_attr()

            sys.__stdout__.flush()
            time.sleep(REVEAL_LOOP_SPEED / 1000)

        termios.tcdrain(sys.stdin)


@contextmanager
def _set_terminal() -> Iterator[None]:
    attr = termios.tcgetattr(sys.stdin)

    new = attr[:]
    new[3] &= ~termios.ICANON & ~termios.ECHO

    termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, new)

    try:
        yield
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSANOW, attr)


def _get_cursor_row() -> int:
    sys.__stdout__.write("\033[6n")
    sys.__stdout__.flush()

    row = 0
    while (c := sys.__stdin__.buffer.read(1)) not in (b";", b"R", b"\x00"):
        if c in (b"\x1b", "["):
            continue

        if c >= b"0" and c <= b"9":
            row = (row * 10) + int(c)

    return row


def _isspace(s: str) -> bool:
    return s in ("\n", "\r")


def _cursor_home() -> None:
    sys.__stdout__.write("\033[H")
    sys.__stdout__.flush()


def _cursor_move(x: int, y: int) -> None:
    sys.__stdout__.write(f"\033[{x};{y}H")
    sys.__stdout__.flush()


def _beep() -> None:
    sys.__stdout__.write("\a")
    sys.__stdout__.flush()


def _bold() -> None:
    sys.__stdout__.write("\033[1m")
    sys.__stdout__.flush()


def _foreground_color(c: int) -> None:
    sys.__stdout__.write(f"\033[3{c}m")
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
