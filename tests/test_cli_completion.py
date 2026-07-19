"""`authkeys completion [bash|zsh|fish]`: non-empty script, exit 0."""

import pytest

from authkeys.cli import run


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_prints_nonempty_script(shell, capsys):
    rc = run(["completion", shell])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() != ""


def test_completion_defaults_to_bash(capsys):
    rc = run(["completion"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "bash" in out.lower() or "compgen" in out
