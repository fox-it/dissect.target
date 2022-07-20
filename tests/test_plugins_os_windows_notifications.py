from dissect.target.plugins.os.windows import notifications

from ._utils import absolute_path


def test_notifications_wpndatabase(target_win_users, fs_win):
    db_file = absolute_path("data/wpndatabase.db")
    fs_win.map_file("users/john/appdata/local/microsoft/windows/notifications/wpndatabase.db", db_file)

    target_win_users.add_plugin(notifications.NotificationsPlugin)

    records = list(target_win_users.notifications.wpndatabase())

    assert len(records) == 3
