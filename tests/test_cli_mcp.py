"""authkeys serves MCP over stdio when ``AUTHKEYS_MCP=stdio`` is set (duho's
default launch trigger), and runs as a normal CLI when it is not."""

import json
import os
import subprocess
import sys
from pathlib import Path

from authkeys.cli import Authkeys

SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_root_does_not_opt_out_of_mcp():
    assert getattr(Authkeys, "_mcp_", True) is True


def _run(env_extra, stdin):
    env = dict(os.environ)
    env.pop("AUTHKEYS_MCP", None)
    env.update(env_extra)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    code = "import sys; from authkeys.cli import run; sys.argv[0] = 'authkeys'; sys.exit(run(sys.argv[1:]))"
    return subprocess.run(
        [sys.executable, "-c", code, "--version"],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=60,
    )


def test_authkeys_mcp_stdio_serves_mcp_tools():
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    proc = _run({"AUTHKEYS_MCP": "stdio"}, "".join(json.dumps(m) + "\n" for m in msgs))
    replies = {}
    for line in proc.stdout.splitlines():
        msg = json.loads(line)
        replies[msg.get("id")] = msg
    assert replies[1]["result"]["serverInfo"]["name"] == "authkeys"
    tools = {t["name"] for t in replies[2]["result"]["tools"]}
    assert "authkeys.resolve" in tools


def test_without_the_variable_it_is_a_normal_cli():
    proc = _run({}, "")
    assert proc.returncode == 0
    assert proc.stdout.startswith("authkeys ")
