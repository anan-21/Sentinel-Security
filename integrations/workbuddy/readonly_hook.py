"""Optional PreToolUse hook for a dedicated CodeBuddy CLI monitoring project.

List exact permitted tool names as administrator-controlled arguments. Returning
an empty object delegates to native permissions. The hook never emits 'allow'.
"""

import json
import sys


def main():
    try:
        raw = sys.stdin.buffer.read(262145)
        if len(raw) > 262144:
            raise ValueError("event too large")
        event = json.loads(raw)
        name = event["tool_name"]
        if (
            event.get("hook_event_name") == "PreToolUse"
            and isinstance(name, str)
            and name in sys.argv[1:]
        ):
            print("{}")
            return
    except (KeyError, ValueError, TypeError, RecursionError):
        pass
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Sentinel: tool outside the monitoring project’s allowlist or incomplete event.",
                }
            }
        )
    )


if __name__ == "__main__":
    main()
