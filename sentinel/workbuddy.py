"""Read the two non-secret connector flags in an explicitly selected WorkBuddy v4 profile.

WorkBuddy 5.5.6 keeps these flags alongside encrypted overrides. We do not decrypt
data, open the credentials store, inspect a marketplace catalog or traverse profiles.
"""

import json
import re
from pathlib import Path

from .discovery import Observation


def configured_connectors(profile, root=None):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", profile):
        raise ValueError("invalid WorkBuddy profile")
    root = Path(root or Path.home() / ".workbuddy" / "connectors")
    folder = root / profile
    path = folder / "connector-states.json"
    if folder.is_symlink() or path.is_symlink() or not path.is_file():
        raise ValueError("profile metadata unavailable")
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("profile metadata too large")
    snapshot = json.loads(raw)
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("version") != 4
        or not isinstance(snapshot.get("connectors"), dict)
    ):
        raise ValueError("unsupported WorkBuddy state format")
    result = []
    for name, flags in snapshot["connectors"].items():
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,160}", name) or not isinstance(
            flags, dict
        ):
            continue
        if flags.get("bound") is not True:
            continue
        enabled = flags.get("enabled")
        state = (
            "enabled"
            if enabled is True
            else "disabled"
            if enabled is False
            else "unknown"
        )
        result.append(Observation(name=name, kind="configured", availability=state))
    return result
