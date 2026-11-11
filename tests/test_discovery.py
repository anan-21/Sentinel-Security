from concurrent.futures import ThreadPoolExecutor
import json
import sys
import subprocess

import pytest
from pydantic import ValidationError
from sentinel.discovery import Observation, discover
from sentinel.history import forget, recall
from sentinel.cli import install
from sentinel.openclaw import configured_channels


def test_channel_versions_and_minimization():
    old = {
        "chat": {"imessage": ["private-account"], "whatsapp": []},
        "auth": [{"token": "SECRET"}],
    }
    new = {
        "chat": {
            "imessage": {"accounts": ["private-account"], "origin": "configured"},
            "matrix": {"accounts": [], "origin": "available"},
        }
    }
    a = configured_channels(old)
    assert a == configured_channels(new)
    report = discover("openclaw", a)
    assert (
        "private-account" not in report.model_dump_json()
        and "SECRET" not in report.model_dump_json()
    )
    assert (
        report.services[0]["evidence"] == ["configured"]
        and report.services[0]["tools"] == []
    )


@pytest.mark.parametrize("host", ["dsh", "workbuddy", "muse", "openclaw", "generic"])
def test_inventory_is_scoped_and_idempotent(host):
    observations = [
        Observation(name="mcp__qq_mail__get_message"),
        Observation(name="qqmail", kind="configured"),
        Observation(name="browser_snapshot"),
        Observation(name="mcp__sentinel__scan_message"),
    ]
    report = discover(host, observations)
    result = {x["service"]: x for x in report.services}
    assert result["qqmail"]["category"] == "email"
    assert result["qqmail"]["operations"] == ["read"]
    assert result["qqmail"]["authorization"] == "unknown"
    assert result["browser"]["suggested_scanner"] == "sentinel_scan_webpage"
    assert "sentinel" not in result
    assert discover(host, observations + observations).services == report.services


def test_disabled_tool_not_proposed_for_use():
    report = discover(
        "workbuddy", [Observation(name="gmail_read", availability="revoked")]
    )
    assert "暂停" in report.services[0]["next_step"]


def test_incomplete_history_stays_historical():
    result = discover(
        "workbuddy",
        [
            Observation(
                name="intranet-site",
                service="old-site",
                category="web",
                kind="previously_seen",
            )
        ],
    )
    assert result.services[0]["evidence"] == ["historical"]
    assert result.services[0]["authorization"] == "unknown"


def test_reject_config_and_private_url():
    for item in [
        {"name": "gmail", "token": "do-not-copy"},
        {"name": "https://example.test/private/path"},
    ]:
        with pytest.raises(ValidationError):
            Observation(**item)


def test_cli_supplied_alias_and_stdin_failure():
    cmd = [
        sys.executable,
        "-m",
        "sentinel.cli",
        "discover",
        "generic",
        "--stdin",
        "--no-local",
    ]
    p = subprocess.run(
        cmd,
        input=json.dumps(
            [{"name": "corp_search", "service": "staff-site", "category": "web"}]
        ),
        text=True,
        capture_output=True,
    )
    assert json.loads(p.stdout)["services"][0]["service"] == "staff-site"
    invalid = subprocess.run(
        cmd, input='{"token":"FAKE_PRIVATE_VALUE"}', text=True, capture_output=True
    )
    assert invalid.returncode and "FAKE_PRIVATE_VALUE" not in invalid.stderr


def test_scoped_history_and_recovery(tmp_path):
    def call(host, profile, rows):
        return recall(host, profile, rows, tmp_path)

    configured = [{"service": "gmail", "evidence": ["configured"]}]
    assert call("workbuddy", "alice", configured) == []
    assert call("workbuddy", "alice", []) == ["gmail"]
    assert call("workbuddy", "bob", []) == []
    assert call("dsh", "alice", []) == []
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert (
            list(pool.map(lambda _: call("workbuddy", "alice", configured), range(12)))
            == [[]] * 12
        )
    forget("workbuddy", "alice", tmp_path)
    assert call("workbuddy", "alice", []) == []


def test_unverified_tools_do_not_enter_connection_history(tmp_path):
    recall(
        "openclaw",
        "demo",
        [{"service": "browser", "evidence": ["tool_visible"]}],
        tmp_path,
    )
    assert recall("openclaw", "demo", [], tmp_path) == []


@pytest.mark.parametrize("host", ["workbuddy", "openclaw", "dsh"])
def test_install_repeat_preserve_user_owned(tmp_path, host):
    from pathlib import Path

    path = Path(install(host, tmp_path))
    timestamp = path.stat().st_mtime_ns
    assert "HOST_ARGUMENT" not in path.read_text()
    assert Path(install(host, tmp_path)).stat().st_mtime_ns == timestamp
    path.write_text("user content")
    with pytest.raises(ValueError):
        install(host, tmp_path)
    assert path.read_text() == "user content"


def test_dsh_registered_is_not_current_authority():
    r = discover("dsh", [Observation(name="gmail_read", kind="registered")]).services[0]
    assert (
        r["evidence"] == ["registered"]
        and r["tools"] == []
        and r["authorization"] == "unknown"
    )


def test_install_preserves_local_edits_with_original_footer(tmp_path):
    from pathlib import Path

    dest = Path(install("dsh", tmp_path))
    edited = "my customization\n" + dest.read_text()
    dest.write_text(edited)
    with pytest.raises(ValueError):
        install("dsh", tmp_path)
    assert dest.read_text() == edited


@pytest.mark.parametrize(
    "link_name", ["sentinel-security", "sentinel-security/SKILL.md"]
)
def test_install_does_not_follow_links(tmp_path, link_name):
    link = tmp_path / "skills" / link_name
    link.parent.mkdir(parents=True)
    other = tmp_path / "unrelated"
    other.mkdir()
    link.symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError):
        install("dsh", tmp_path / "skills")
    assert list(other.iterdir()) == []


def test_history_does_not_follow_links(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (state / "sentinel-security").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        recall("workbuddy", "testing", [], state)
    with pytest.raises(ValueError):
        forget("workbuddy", "testing", state)
    assert list(outside.iterdir()) == []
