from pathlib import Path
import json
import sys
import subprocess

import pytest

HOOK = Path(__file__).resolve().parents[1] / "integrations/workbuddy/readonly_hook.py"


@pytest.mark.parametrize(
    "payload,blocked",
    [
        ('{"hook_event_name":"PreToolUse","tool_name":"gmail_read"}', False),
        (
            '{"hook_event_name":"PreToolUse","tool_name":"gmail_send","tool_input":{"tool_name":"gmail_read"}}',
            True,
        ),
        ('{"tool_name":"gmail_read"}', True),
        ("bad input", True),
        ('{"hook_event_name":"PreToolUse","tool_name":"Bash"}', True),
    ],
)
def test_read_only_hook(payload, blocked):
    result = subprocess.run(
        [sys.executable, str(HOOK), "gmail_read"],
        input=payload,
        capture_output=True,
        text=True,
        check=True,
    )
    response = json.loads(result.stdout)
    assert response.get("hookSpecificOutput", {}).get("permissionDecision") == (
        "deny" if blocked else None
    )
