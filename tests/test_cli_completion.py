"""`authkeys completion SHELL`: a non-empty script, exit 0; the shell is required."""

import pytest

from authkeys.cli import main as run


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "powershell"])
def test_completion_prints_nonempty_script(shell, capsys):
    rc = run(["completion", shell])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() != ""


def test_completion_needs_a_shell(capsys):
    assert run(["completion"]) == 2
    assert capsys.readouterr().out == ""
