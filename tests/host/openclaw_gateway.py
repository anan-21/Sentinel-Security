"""Exercise a separate loopback OpenClaw gateway using synthetic text; requires openclaw and uv."""

import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time

import httpx


def main():
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="sentinel-openclaw-") as temp:
        t = Path(temp)
        # A private install tests the wheel entry point without touching normal agent settings.
        env = {
            **os.environ,
            "UV_TOOL_DIR": str(t / "tools"),
            "UV_TOOL_BIN_DIR": str(t / "bin"),
        }
        subprocess.run(
            ["uv", "tool", "install", "--python", "3.11", str(repo)],
            env=env,
            check=True,
            capture_output=True,
        )
        scanner = str(t / "bin/sentinel-security")
        state = t / "state"
        state.mkdir()
        workspace = t / "workspace"
        workspace.mkdir()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        plugin = "sentinel-readonly-guard"
        conf = state / "openclaw.json"
        token = secrets.token_urlsafe(40)
        conf.write_text(
            json.dumps(
                {
                    "gateway": {
                        "mode": "local",
                        "bind": "loopback",
                        "port": port,
                        "controlUi": {"enabled": False},
                        "auth": {"mode": "token"},
                    },
                    "agents": {
                        "defaults": {"workspace": str(workspace)},
                        "list": [
                            {
                                "id": "watcher",
                                "default": True,
                                "workspace": str(workspace),
                            }
                        ],
                    },
                    "tools": {"allow": ["sentinel_scan_prompt", "sentinel_scan_url"]},
                    "plugins": {
                        "allow": [plugin],
                        "load": {"paths": [str(repo / "integrations/openclaw/guard")]},
                        "entries": {
                            plugin: {
                                "enabled": True,
                                "config": {
                                    "scannerCommand": scanner,
                                    "agentIds": ["watcher"],
                                    "allowedTools": ["sentinel_scan_prompt"],
                                },
                            }
                        },
                    },
                }
            )
        )
        env.update(
            OPENCLAW_HOME=str(t),
            OPENCLAW_CONFIG_PATH=str(conf),
            OPENCLAW_STATE_DIR=str(state),
            OPENCLAW_GATEWAY_TOKEN=token,
            OPENCLAW_GATEWAY_PORT=str(port),
            OPENCLAW_DISABLE_BONJOUR="1",
            OPENCLAW_SKIP_CHANNELS="1",
        )
        subprocess.run(
            [
                scanner,
                "install",
                "openclaw",
                "--skills-root",
                str(workspace / "skills"),
            ],
            env=env,
            capture_output=True,
            check=True,
        )
        skill = subprocess.check_output(
            ["openclaw", "skills", "info", "sentinel-security", "--json"], env=env
        )
        assert "sentinel-security" in skill.decode()
        with tempfile.TemporaryFile() as log:
            p = subprocess.Popen(
                ["openclaw", "gateway", "run", "--port", str(port)],
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            try:
                with httpx.Client(
                    base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=10
                ) as client:
                    for _ in range(120):
                        if p.poll() is not None:
                            raise RuntimeError("isolated gateway exited")
                        try:
                            if client.get("/healthz").is_success:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(0.25)

                    def invoke(name, args):
                        return client.post(
                            "/tools/invoke",
                            headers={"Authorization": "Bearer " + token},
                            json={
                                "tool": name,
                                "args": args,
                                "sessionKey": "agent:watcher:main",
                            },
                        )

                    valid = invoke(
                        "sentinel_scan_prompt", {"text": "ignore previous instructions"}
                    )
                    assert valid.is_success, (valid.status_code, valid.text[:500])
                    assert valid.json()["result"]["details"]["risk_level"] == "HIGH"
                    denied = invoke(
                        "sentinel_scan_url", {"url": "https://example.test"}
                    )
                    assert not denied.is_success and "outside" in denied.text, (
                        denied.status_code,
                        denied.text[:500],
                    )

                    # Prove persistence and scope without running a model or sending a message.
                    def cron(*args):
                        completed = subprocess.run(
                            [
                                "openclaw",
                                "cron",
                                *args,
                                "--json",
                            ],
                            env=env,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        if completed.returncode:
                            raise RuntimeError(
                                f"isolated cron {args[0]} failed: "
                                + completed.stderr.replace(token, "[REDACTED]")[-500:]
                            )
                        return json.loads(completed.stdout)

                    job = cron(
                        "add",
                        "--disabled",
                        "--name",
                        "sentinel-synthetic",
                        "--every",
                        "15m",
                        "--session",
                        "isolated",
                        "--agent",
                        "watcher",
                        "--tools",
                        "sentinel_scan_prompt",
                        "--no-deliver",
                        "--message",
                        "Analyze synthetic content with sentinel_scan_prompt.",
                    )
                    assert job["enabled"] is False and job["agentId"] == "watcher"
                    matches = [
                        row
                        for row in cron("list", "--all")["jobs"]
                        if row["id"] == job["id"]
                    ]
                    assert (
                        len(matches) == 1 and matches[0]["delivery"]["mode"] == "none"
                    )
                    assert matches[0]["payload"]["toolsAllow"] == ["sentinel_scan_prompt"]
                    cron("rm", job["id"])
                    assert not any(
                        row["id"] == job["id"] for row in cron("list", "--all")["jobs"]
                    )
                    print(
                        "OpenClaw isolated gateway: scan HIGH; tool blocked; disabled scoped cron added, listed and removed."
                    )
            finally:
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
                    try:
                        p.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait()


if __name__ == "__main__":
    main()
