"""`Authkeys._mcp_ = False` opts the whole CLI out of duho's
``AUTHKEYS_MCP=stdio`` auto-launch trigger.

authkeys is a credentials tool: an MCP-exposed `resolve`/`check` would hand a
caller a user's real `authorized_keys` content, and MCP-exposed `serve`
would start a listener as the side effect of a single tool call. Neither is
a safe default here (see CHANGELOG), so the opt-out must actually hold: a
normal CLI run must proceed even when the trigger env var is set, never
diverting into serving MCP tools over stdio.
"""

import os

import pytest

from authkeys.cli import Authkeys, run


def test_root_declares_mcp_opt_out():
    assert Authkeys._mcp_ is False


def test_authkeys_mcp_stdio_env_does_not_start_mcp_server(monkeypatch, capsys):
    # Without the opt-out, duho's `<NAME>_MCP=stdio` trigger diverts
    # `main()`/`app()` into serving MCP tools over stdio instead of parsing
    # argv or running any command -- no version text, no exit via argparse.
    # Prove the opt-out disables that: a normal CLI run (`--version`) is
    # identical whether or not AUTHKEYS_MCP is set.
    monkeypatch.delenv("AUTHKEYS_MCP", raising=False)
    with pytest.raises(SystemExit) as baseline:
        run(["--version"])
    baseline_out = capsys.readouterr().out

    monkeypatch.setenv("AUTHKEYS_MCP", "stdio")
    with pytest.raises(SystemExit) as with_env:
        run(["--version"])
    with_env_out = capsys.readouterr().out

    assert with_env.value.code == baseline.value.code == 0
    assert with_env_out == baseline_out
    assert with_env_out.strip() != ""
    # Never popped: `_mcp_ = False` returns before the trigger touches the
    # environment at all, so a real MCP-aware child process downstream would
    # still see whatever the caller set.
    assert os.environ.get("AUTHKEYS_MCP") == "stdio"
