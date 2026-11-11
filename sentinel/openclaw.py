"""Project channel metadata only. Auth profiles, labels and account IDs never leave this adapter."""

import json
import subprocess
from .discovery import Observation
import re


def configured_channels(payload: dict) -> list[Observation]:
    chat = payload.get("chat")
    if not isinstance(chat, dict):
        raise ValueError("OpenClaw 返回了无法识别的渠道清单")
    rows = []
    for name, value in chat.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", name):
            continue
        if isinstance(value, dict):
            if value.get("origin") != "configured":
                continue
            accounts = value.get("accounts")
        else:
            accounts = value
        if isinstance(accounts, list) and accounts:
            rows.append(
                Observation(name=name, service=name, category="chat", kind="configured")
            )
    return rows


def local_channels() -> list[Observation]:
    # Releases before the provider-usage split require --no-usage for an offline inventory.
    base = ["openclaw", "channels", "list"]
    help_text = subprocess.run(
        [*base, "--help"], capture_output=True, timeout=20, check=True
    ).stdout
    flags = ["--json"]
    if b"--no-usage" in help_text:
        flags.append("--no-usage")
    result = subprocess.run(
        [*base, *flags], capture_output=True, timeout=30, check=True
    )
    return configured_channels(json.loads(result.stdout))
