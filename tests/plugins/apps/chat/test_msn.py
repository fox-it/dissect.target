from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.chat.msn import MSNPlugin, convert_email
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_msn(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we parse MSN Chat messages on Windows XP correctly."""

    morpheus_id = convert_email("morpheus@matrix.internal")
    neo_id = convert_email("neo@matrix.internal")

    assert morpheus_id == 2450688751
    assert neo_id == 4092013818

    fs_win.makedirs(f"Users/John/Application Data/Microsoft/MSN Messenger/{morpheus_id}")
    fs_win.map_file(
        f"Users/John/My Documents/My Received Files/morpheus{morpheus_id}/History/neo{neo_id}.xml",
        absolute_path("_data/plugins/apps/chat/msn/history.xml"),
    )

    target_win_users.add_plugin(MSNPlugin)
    assert len(target_win_users.msn.installs) == 1

    results = list(target_win_users.msn.history())
    assert len(results) == 35

    assert results[0].username == "John"
    assert results[0].hostname is None

    assert results[0].ts == datetime(2025, 4, 1, 13, 37, 0, tzinfo=timezone.utc)
    assert results[0].client == "msn"
    assert results[0].account == str(morpheus_id)
    assert results[0].sender == "morpheus@matrix.internal"
    assert results[0].recipient == "neo@matrix.internal"

    assert [(r.sender.replace("@matrix.internal", ""), r.message) for r in results] == [
        (
            "morpheus",
            "At last.",
        ),
        (
            "morpheus",
            "Welcome, Neo. As you no doubt have guessed, I am Morpheus.",
        ),
        (
            "neo",
            "It's an honor.",
        ),
        (
            "morpheus",
            "No, the honor is mine. Please. Come. Sit.",
        ),
        (
            "morpheus",
            "I imagine, right now, you must be feeling a bit like Alice, tumbling down the rabbit hole?",
        ),
        (
            "neo",
            "You could say that.",
        ),
        (
            "morpheus",
            "I can see it in your eyes. You have the look of a man who accepts "
            "what he sees because he is expecting to wake up.",
        ),
        (
            "morpheus",
            "Ironically, this is not far from the truth. But I'm getting ahead of "
            "myself. Can you tell me, Neo, why are you here?",
        ),
        (
            "neo",
            "You're Morpheus. You're a legend. Most hackers would die to meet you.",
        ),
        (
            "morpheus",
            "Yes. Thank you. But I think we both know there's more to it than that. Do you believe in fate, Neo?",
        ),
        (
            "neo",
            "No.",
        ),
        (
            "morpheus",
            "Why not?",
        ),
        (
            "neo",
            "Because I don't like the idea that I'm not in control of my life.",
        ),
        (
            "morpheus",
            "I know exactly what you mean.",
        ),
        (
            "morpheus",
            "Let me tell you why you are here. You have come because you know something.",
        ),
        (
            "morpheus",
            "What you know you can't explain but you feel it.",
        ),
        (
            "morpheus",
            "You've felt it your whole life, felt that something is wrong with the world.",
        ),
        (
            "morpheus",
            "You don't know what, but it's there like a splinter in your mind, "
            "driving you mad. It is this feeling that brought you to me.",
        ),
        (
            "morpheus",
            "Do you know what I'm talking about?",
        ),
        (
            "neo",
            "The Matrix?",
        ),
        (
            "morpheus",
            "Do you want to know what it is?",
        ),
        (
            "morpheus",
            "The Matrix is everywhere, it's all around us, here even in this room.",
        ),
        (
            "morpheus",
            "You can see it out your window or on your television. You feel it "
            "when you go to work, or go to church or pay your taxes.",
        ),
        (
            "morpheus",
            "It is the world that has been pulled over your eyes to blind you from the truth.",
        ),
        (
            "neo",
            "What truth?",
        ),
        (
            "morpheus",
            "That you are a slave, Neo. Like everyone else, you were born into "
            "bondage, kept inside a prison that you cannot smell, taste, or touch.",
        ),
        (
            "morpheus",
            "A prison for your mind.",
        ),
        (
            "morpheus",
            "Unfortunately, no one can be told what the Matrix is.",
        ),
        (
            "morpheus",
            "You have to see it for yourself.",
        ),
        (
            "morpheus",
            "This is your last chance. After this, there is no going back.",
        ),
        (
            "morpheus",
            "You take the blue pill and the story ends.",
        ),
        (
            "morpheus",
            "You wake in your bed and you believe whatever you want to believe.",
        ),
        (
            "morpheus",
            "You take the red pill and you stay in Wonderland and I show you how deep the rabbit-hole goes.",
        ),
        (
            "morpheus",
            "Remember that all I am offering is the truth. Nothing more.",
        ),
        (
            "morpheus",
            "Follow me.",
        ),
    ]
