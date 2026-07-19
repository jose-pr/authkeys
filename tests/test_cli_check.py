"""`authkeys check <user>`: resolved keys on stdout, per-source trace logged.

The per-source trace goes through the stdlib `logging` module (duho's
`init_stderr_logging` attaches a `StreamHandler(sys.stderr)` once per
process), so it is asserted via pytest's `caplog` fixture rather than
`capsys` -- a handler created before pytest's per-test stderr capture swap
would otherwise hold a stale `sys.stderr` reference and the assertion would
flake depending on test order. `caplog` observes the log records directly,
independent of that ordering. Manually verified end-to-end (outside pytest)
that the "Using source: ..." line does land on the real stderr stream.
"""

import logging
import sys
import types

from authkeys.cli import run

RSA = "ssh-rsa AAAAB3Nza"


def test_check_prints_key_to_stdout_and_traces_per_source(
    tmp_path, capsys, caplog, monkeypatch
):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(RSA + "\n")
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwnam = lambda n: types.SimpleNamespace(pw_name=n, pw_dir=str(home))
    fake_pwd.getpwuid = lambda u: types.SimpleNamespace(pw_name="alice", pw_dir=str(home))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)

    conf = tmp_path / "authkeys.conf"
    conf.write_text(
        "[cache]\n[source:files]\nbackend = authkeys.sources.authorizedkeys\n"
    )

    with caplog.at_level(logging.INFO, logger="authkeys"):
        rc = run(["check", "alice", "--config", str(conf)])
    out = capsys.readouterr()

    assert rc == 0
    assert RSA in out.out
    # Per-source tracing (the "Using source: ..." INFO line) is a log record,
    # not part of stdout -- stdout must carry only key lines.
    assert any("Using source" in r.message for r in caplog.records)
    assert "Using source" not in out.out
