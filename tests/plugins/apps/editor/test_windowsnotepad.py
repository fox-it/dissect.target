from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.editor.windowsnotepad import (
    WindowsNotepadPlugin,
    WindowsNotepadTab,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

text1 = "This is an unsaved tab, UTF-8 encoded with Windows (CRLF). It's only 88 characters long."
text2 = "Dissect は、インシデント対応のための優れたフレームワークです。 The Notepad window shows UTF-8 as the encoding. This text has 113 characters."  # noqa: E501
text3 = "This is a very short text."
text4 = "This is another short test. And we should be able to parse this."
text5 = "This is a test and the text is longer than 256 bytes. "
text6 = "This is a test and the text is longer than 65536 bytes. "
text7 = "This a text, which is nothing special. But I am going to modify it a bit. For example, I have removed quote some stuff. Adding a word in the beginning now... At this point, I've edited it quite a lot."  # noqa: E501
text8 = "Closing application now. It's saved but now I'm adding unsaved changes and closing the application again. Dit a few deletions!"  # noqa: E501
loremipsum = "Lorem ipsum dolor sit amet. Eum error blanditiis eum pariatur delectus ut consequuntur officiis a excepturi dignissimos et doloribus quia 33 perspiciatis soluta nam perspiciatis dolor. Ut repudiandae quidem cum sint modi qui sint consequatur. Aut autem quidem eum enim consequatur qui voluptate consequatur non similique voluptate. A vitae modi vel sint provident ut galisum tenetur sit voluptatem amet. Est impedit perspiciatis est repudiandae voluptates ut fugit alias! Eum magni esse aut velit illum qui excepturi aperiam. Ex dolores asperiores ut debitis omnis qui consequuntur dolore. Est voluptatem mollitia et quibusdam unde ea accusamus fuga. Cum quis galisum et impedit sunt qui aliquam perspiciatis sed modi quidem qui nisi molestias. Aut temporibus architecto ut neque voluptatem et consequatur deleniti sed accusantium quibusdam et omnis dignissimos ad rerum ipsam et rerum quia. Ut nihil repellat et eaque molestias quo iusto ipsum At optio sint eos quidem earum?\r\rEx deleniti unde eum tenetur rerum ea dolore numquam? Eos aperiam officiis et neque explicabo et enim atque ut eaque omnis non illum eveniet est molestias itaque et ratione voluptatem. Ea deserunt nemo et quos tempora et nostrum aperiam sit necessitatibus illo sit culpa placeat. Vel tempore quibusdam ut velit voluptate aut odio facere non voluptas earum est odio galisum et voluptas harum. Et blanditiis sapiente et nostrum laborum aut voluptatem explicabo a quasi assumenda. Est voluptatem quia eum minima galisum quo totam excepturi aut facilis enim vel voluptate repudiandae sit distinctio laboriosam. Quo possimus molestiae et molestiae accusantium est voluptas omnis sed obcaecati natus. Non vitae asperiores qui nostrum enim id saepe fugiat et incidunt quasi.\r\rEos ipsa facilis aut excepturi voluptatem a omnis magni vel magni iste. Sed ipsum consequatur qui reprehenderit deleniti et soluta molestiae. Ut vero assumenda id dolor ipsum in deleniti voluptatem aut quis quisquam sed repudiandae temporibus ab quia inventore. Sed velit fugit vel facere cumque et delectus ullam sed eaque impedit. Est veritatis dignissimos aut doloribus dolorem vel pariatur repellendus sit nesciunt similique eum architecto quia. Ea expedita veritatis eum dolorem molestiae ut enim fugit aut beatae quibusdam. Aut voluptas natus in quidem deleniti aut animi iure est incidunt tenetur qui culpa maiores! Et nostrum quaerat qui consequatur consequatur aut aliquam atque aut praesentium rerum et consequuntur exercitationem. Non accusantium ipsa vel consectetur vitae ut magnam autem et natus rerum ut consectetur inventore est doloremque temporibus 33 dolores doloribus! Aut perferendis optio et nostrum repellendus et fugit itaque ut nisi neque sed sint quaerat. Aut placeat architecto et eius sapiente eum molestiae quam. Quo mollitia sapiente non Quis neque non tempora laudantium. Quo distinctio quos et molestias natus sit veritatis consequuntur aut repellendus neque a porro galisum cum numquam nesciunt et animi earum? Aut dolorum dolore non assumenda omnis et molestiae amet id sint vero est eligendi harum sit temporibus magnam aut ipsam quos.\r\r"  # noqa: E501


def test_windows_tab_parsing() -> None:
    # Standalone parsing of tab files, so not using the plugin
    tab_file = Path(absolute_path("_data/plugins/apps/texteditor/windowsnotepad/unsaved-with-deletions.bin"))
    content = WindowsNotepadTab(tab_file)
    assert content.content == "Not saved aasdflasd"
    assert repr(content) == "<WindowsNotepadTab saved=False content_size=19 has_deleted_content=True>"


def test_windows_tab_plugin_deleted_contents(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path, target_win_users: Target
) -> None:
    file_text_map = {
        "unsaved-with-deletions.bin": ("Not saved aasdflasd", "snUlltllafds tjkf"),
        "lots-of-deletions.bin": (
            "This a text, which is nothing special. But I am going to modify it a bit. "
            "For example, I have removed quote some stuff. "
            "Adding a word in the beginning now... "
            "At this point, I've edited it quite a lot.",
            "b a ,elpmac ydaerlae already thi laiceps emos",
        ),
    }

    tabcache = absolute_path("_data/plugins/apps/texteditor/windowsnotepad/")

    user = target_win_users.user_details.find(username="John")
    tab_dir = user.home_path.joinpath(
        "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState"
    )

    fs_win.map_dir("Users\\John", tmp_path)

    for file in file_text_map:
        tab_file = str(tab_dir.joinpath(file))[3:]
        fs_win.map_file(tab_file, tabcache.joinpath(file))

    target_win.add_plugin(WindowsNotepadPlugin)

    records = list(target_win.windowsnotepad.tabs())

    # Check the amount of files
    assert len(list(tab_dir.iterdir())) == len(file_text_map.keys())
    assert len(records) == len(file_text_map.keys())

    # The recovered content in the records should match the original data, as well as the length
    for rec in records:
        assert rec.editor == "windowsnotepad"
        assert rec.content == file_text_map[rec.path.name][0]
        assert rec.deleted_content == file_text_map[rec.path.name][1]
        assert rec.source is not None


def test_windows_tab_plugin_default(
    target_win: Target,
    fs_win: VirtualFilesystem,
    tmp_path: Path,
    target_win_users: Target,
    caplog: pytest.LogCaptureFixture,
) -> None:
    file_text_map = {
        "c515e86f-08b3-4d76-844a-cddfcd43fcbb.bin": (text1, None),
        "85167c9d-aac2-4469-ae44-db5dccf8f7f4.bin": (text2, None),
        "dae80df8-e1e5-4996-87fe-b453f63fcb19.bin": (text3, "THis is "),
        "3f915e17-cf6c-462b-9bd1-2f23314cb979.bin": (text4, None),
        "ba291ccd-f1c3-4ca8-949c-c01f6633789d.bin": ((text5 * 5), None),
        "e609218e-94f2-45fa-84e2-f29df2190b26.bin": ((text6 * 1260), None),
        "3d0cc86e-dfc9-4f16-b74a-918c2c24188c.bin": (loremipsum, None),
        "wrong-checksum.bin": (text4, None),  # only added to check for corrupt checksum, not validity
        "cfe38135-9dca-4480-944f-d5ea0e1e589f.bin": (
            (loremipsum * 37)[:-2],
            None,
        ),  # removed the two newlines in this file
        "saved.bin": ("Saved!", None),
        "unsaved.bin": ("Not saved at all", "snUllt"),
        "unsaved-with-deletions.bin": ("Not saved aasdflasd", "snUlltllafds tjkf"),
        "lots-of-deletions.bin": (text7, "b a ,elpmac ydaerlae already thi laiceps emos"),
        "appclosed_saved_and_deletions.bin": (text8, None),
        "appclosed_unsaved.bin": ("Closing application now", None),
        "new-format.bin": ("", None),
        "stored_unsaved_with_new_data.bin": ("Stored to disk but unsaved, but with extra data.", None),
    }

    tabcache = absolute_path("_data/plugins/apps/texteditor/windowsnotepad/")

    user = target_win_users.user_details.find(username="John")
    tab_dir = user.home_path.joinpath(
        "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState"
    )

    fs_win.map_dir("Users\\John", tmp_path)

    for file in file_text_map:
        tab_file = str(tab_dir.joinpath(file))[3:]
        fs_win.map_file(tab_file, tabcache.joinpath(file))

    target_win.add_plugin(WindowsNotepadPlugin)

    records = list(target_win.windowsnotepad.tabs())

    # Check the amount of files
    assert len(list(tab_dir.iterdir())) == len(file_text_map.keys())
    assert len(records) == len(file_text_map.keys())

    for line in caplog.text.split("\n"):
        # One file should still return contents, but there should be an entry for in the logging for a CRC missmatch.
        assert (
            "CRC32 mismatch in single-block file: wrong-checksum.bin (expected=deadbeef, actual=a48d30a6)" in line
            or "CRC32 mismatch" not in line
        )

    # The recovered content in the records should match the original data, as well as the length
    for rec in records:
        assert rec.editor == "windowsnotepad"
        assert rec.content == file_text_map[rec.path.name][0]
        assert rec.deleted_content == file_text_map[rec.path.name][1]
        assert rec.source is not None


def test_windows_saved_tab_plugin_extra_fields(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path, target_win_users: Target
) -> None:
    file_text_map = {
        "saved.bin": (
            "Saved!",
            "C:\\Users\\user\\Desktop\\Saved!.txt",
            datetime(2024, 3, 28, 13, 7, 55, 482183, tzinfo=timezone.utc),
            "ed9b760289e614c9dc8776e7280abe870be0a85019a32220b35acc54c0ecfbc1",
        ),
        "appclosed_saved_and_deletions.bin": (
            text8,
            "C:\\Users\\user\\Desktop\\Saved.txt",
            datetime(2024, 3, 28, 13, 16, 21, 158279, tzinfo=timezone.utc),
            "8d0533144aa42e2d81e7474332bdef6473e42b699041528d55a62e5391e914ce",
        ),
    }

    tabcache = absolute_path("_data/plugins/apps/texteditor/windowsnotepad/")

    user = target_win_users.user_details.find(username="John")
    tab_dir = user.home_path.joinpath(
        "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState"
    )

    fs_win.map_dir("Users\\John", tmp_path)

    for file in file_text_map:
        tab_file = str(tab_dir.joinpath(file))[3:]
        fs_win.map_file(tab_file, tabcache.joinpath(file))

    target_win.add_plugin(WindowsNotepadPlugin)

    records = list(target_win.windowsnotepad.tabs())

    # Check the amount of files
    assert len(list(tab_dir.iterdir())) == len(file_text_map.keys())
    assert len(records) == len(file_text_map.keys())

    # The recovered content in the records should match the original data, as well as the length and all the
    # other saved metadata
    for rec in records:
        assert rec.editor == "windowsnotepad"
        assert len(rec.content) == len(file_text_map[rec.path.name][0])
        assert rec.content == file_text_map[rec.path.name][0]
        assert rec.saved_path == file_text_map[rec.path.name][1]
        assert rec.ts == file_text_map[rec.path.name][2]
        assert rec.digest.sha256 == file_text_map[rec.path.name][3]
        assert rec.source is not None
