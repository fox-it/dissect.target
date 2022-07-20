from dissect.target.tools import shell
from dissect.target.tools.shell import TargetCli


def test_target_cli_ls(target_win, capsys, monkeypatch):

    # disable colorful output in `target-shell`
    monkeypatch.setattr(shell, "LS_COLORS", {})

    cli = TargetCli(target_win)
    cli.onecmd("ls")

    captured = capsys.readouterr()
    assert captured.out == "\n".join(["C:", "sysvol"]) + "\n"
