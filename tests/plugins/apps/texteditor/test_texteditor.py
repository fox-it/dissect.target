import os

from dissect.target.plugins.apps.texteditor import windowsnotepad
from tests._utils import absolute_path

text1 = "This is an unsaved tab, UTF-8 encoded with Windows (CRLF). It's only 88 characters long."
text2 = (
    "Dissect は、インシデント対応のための優れたフレームワークです。 The Notepad window shows UTF-8 as the encoding. This text has 113 "
    "characters."
)
text3 = "This is a very short text."
text4 = "This is another short test. And we should be able to parse this."
text5 = "This is a test and the text is longer than 256 bytes. "
text6 = "This is a test and the text is longer than 65536 bytes. "
loremipsum = """Lorem ipsum dolor sit amet. Eum error blanditiis eum pariatur delectus ut consequuntur officiis a excepturi dignissimos et doloribus quia 33 perspiciatis soluta nam perspiciatis dolor. Ut repudiandae quidem cum sint modi qui sint consequatur. Aut autem quidem eum enim consequatur qui voluptate consequatur non similique voluptate. A vitae modi vel sint provident ut galisum tenetur sit voluptatem amet. Est impedit perspiciatis est repudiandae voluptates ut fugit alias! Eum magni esse aut velit illum qui excepturi aperiam. Ex dolores asperiores ut debitis omnis qui consequuntur dolore. Est voluptatem mollitia et quibusdam unde ea accusamus fuga. Cum quis galisum et impedit sunt qui aliquam perspiciatis sed modi quidem qui nisi molestias. Aut temporibus architecto ut neque voluptatem et consequatur deleniti sed accusantium quibusdam et omnis dignissimos ad rerum ipsam et rerum quia. Ut nihil repellat et eaque molestias quo iusto ipsum At optio sint eos quidem earum?\r\rEx deleniti unde eum tenetur rerum ea dolore numquam? Eos aperiam officiis et neque explicabo et enim atque ut eaque omnis non illum eveniet est molestias itaque et ratione voluptatem. Ea deserunt nemo et quos tempora et nostrum aperiam sit necessitatibus illo sit culpa placeat. Vel tempore quibusdam ut velit voluptate aut odio facere non voluptas earum est odio galisum et voluptas harum. Et blanditiis sapiente et nostrum laborum aut voluptatem explicabo a quasi assumenda. Est voluptatem quia eum minima galisum quo totam excepturi aut facilis enim vel voluptate repudiandae sit distinctio laboriosam. Quo possimus molestiae et molestiae accusantium est voluptas omnis sed obcaecati natus. Non vitae asperiores qui nostrum enim id saepe fugiat et incidunt quasi.\r\rEos ipsa facilis aut excepturi voluptatem a omnis magni vel magni iste. Sed ipsum consequatur qui reprehenderit deleniti et soluta molestiae. Ut vero assumenda id dolor ipsum in deleniti voluptatem aut quis quisquam sed repudiandae temporibus ab quia inventore. Sed velit fugit vel facere cumque et delectus ullam sed eaque impedit. Est veritatis dignissimos aut doloribus dolorem vel pariatur repellendus sit nesciunt similique eum architecto quia. Ea expedita veritatis eum dolorem molestiae ut enim fugit aut beatae quibusdam. Aut voluptas natus in quidem deleniti aut animi iure est incidunt tenetur qui culpa maiores! Et nostrum quaerat qui consequatur consequatur aut aliquam atque aut praesentium rerum et consequuntur exercitationem. Non accusantium ipsa vel consectetur vitae ut magnam autem et natus rerum ut consectetur inventore est doloremque temporibus 33 dolores doloribus! Aut perferendis optio et nostrum repellendus et fugit itaque ut nisi neque sed sint quaerat. Aut placeat architecto et eius sapiente eum molestiae quam. Quo mollitia sapiente non Quis neque non tempora laudantium. Quo distinctio quos et molestias natus sit veritatis consequuntur aut repellendus neque a porro galisum cum numquam nesciunt et animi earum? Aut dolorum dolore non assumenda omnis et molestiae amet id sint vero est eligendi harum sit temporibus magnam aut ipsam quos.\r\r"""  # noqa: E501


def test_texteditor_plugin(target_win, fs_win, tmp_path, target_win_users, caplog):
    file_text_map = {
        "c515e86f-08b3-4d76-844a-cddfcd43fcbb.bin": text1,
        "85167c9d-aac2-4469-ae44-db5dccf8f7f4.bin": text2,
        "dae80df8-e1e5-4996-87fe-b453f63fcb19.bin": text3,
        "3f915e17-cf6c-462b-9bd1-2f23314cb979.bin": text4,
        "ba291ccd-f1c3-4ca8-949c-c01f6633789d.bin": (text5 * 5),
        "e609218e-94f2-45fa-84e2-f29df2190b26.bin": (text6 * 1260),
        "3d0cc86e-dfc9-4f16-b74a-918c2c24188c.bin": loremipsum,
        "wrong-checksum.bin": "",  # only added to check for corrupt checksum, not validity
        "cfe38135-9dca-4480-944f-d5ea0e1e589f.bin": (loremipsum * 37)[:-2],  # removed the two newlines in this file
    }

    tabcache = absolute_path("_data/plugins/apps/texteditor/windowsnotepad/")

    user = target_win_users.user_details.find(username="John")
    tab_dir = user.home_path.joinpath(windowsnotepad.WindowsNotepadPlugin.DIRECTORY)

    fs_win.map_dir("Users\\John", tmp_path)

    for file in file_text_map.keys():
        tab_file = str(tab_dir.joinpath(file))[3:]
        fs_win.map_file(tab_file, os.path.join(tabcache, file))

    target_win.add_plugin(windowsnotepad.WindowsNotepadPlugin)

    records = list(target_win.windowsnotepad.tabs())

    # Check the amount of files
    assert len(list(tab_dir.iterdir())) == len(file_text_map.keys())

    # Only one should not be parsed correctly, without errors/warnings
    assert len(records) == len(file_text_map.keys()) - 1

    # One file should not return any contents, there should be an entry for this in the logging.
    assert "CRC32 checksum mismatch in file: wrong-checksum.bin" in caplog.text
    assert (
        "CRCMismatchException: CRC32 mismatch in single-block file. expected=deadbeef, actual=a48d30a6" in caplog.text
    )

    # The recovered content in the records should match the original data, as well as the length
    for rec in records:
        assert rec.content == file_text_map[rec.filename]
        assert len(rec.content) == len(file_text_map[rec.filename])
