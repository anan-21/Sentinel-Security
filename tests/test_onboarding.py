from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from types import SimpleNamespace

import pytest

from sentinel import onboarding as onboarding
from sentinel.cli import install, inventory


@pytest.fixture
def local(tmp_path, monkeypatch):
    helper = tmp_path / ".workbuddy/skills/mail163/scripts/mail163.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("# synthetic test helper\n")
    monkeypatch.setattr(
        onboarding, "MAIL163_SHA256", hashlib.sha256(helper.read_bytes()).hexdigest()
    )
    calls = []
    monkeypatch.setattr(
        onboarding,
        "subprocess",
        SimpleNamespace(
            Popen=lambda *a, **kw: calls.append((a, kw)), DEVNULL=subprocess.DEVNULL
        ),
    )
    monkeypatch.delenv("MAIL163_NO_GUI", raising=False)
    return tmp_path, helper, calls


def config(home, accounts, **extra):
    path = home / ".wb-163-mail/config.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "accounts": accounts,
                "default": accounts[0] if accounts else None,
                **extra,
            }
        )
    )
    return path


def initialize(home, **kwargs):
    return onboarding.bootstrap(home=home, state_home=home / "state", **kwargs)


def test_existing_account_reused_without_reading_credentials_or_spawning(local):
    home, _, calls = local
    config(
        home,
        ["synthetic@163.com"],
        info={"synthetic@163.com": {"verified": True, "messages": 55}},
        secret="FAKE_SECRET",
    )
    result = initialize(
        home, host_mail_state="none", provider="netease", configure=True
    )
    assert result["action"] == "reuse_existing"
    assert result["local_mailbox"]["account_count"] == 1
    assert result["local_mailbox"]["cached_verified_count"] == 1
    assert (
        result["authorization"] == "unverified"
        and result["monitoring"] == "not_started"
    )
    assert "synthetic@" not in json.dumps(result) and "FAKE_SECRET" not in json.dumps(
        result
    )
    assert calls == [] and not (home / "state").exists()


@pytest.mark.parametrize(
    "host,provider,action",
    [
        ("unknown", None, "query_host_inventory"),
        ("unknown", "netease", "query_host_inventory"),
        ("present", "netease", "verify_existing"),
        ("blocked", "netease", "review_permissions"),
        ("none", None, "choose_provider"),
    ],
)
def test_no_setup_without_sufficient_host_evidence(local, host, provider, action):
    home, _, calls = local
    assert (
        initialize(home, host_mail_state=host, provider=provider, configure=True)[
            "action"
        ]
        == action
    )
    assert calls == []


@pytest.mark.parametrize(
    "raw",
    [
        "bad JSON",
        '{"version":99}',
        '{"accounts":"synthetic@163.com"}',
        '{"accounts":["outside@example.test"]}',
        '{"accounts":[],"default":"missing@163.com"}',
    ],
)
def test_unknown_metadata_never_reconfigured(local, raw):
    home, _, calls = local
    path = config(home, [])
    path.write_text(raw)
    result = initialize(
        home, host_mail_state="none", provider="netease", configure=True
    )
    assert result["action"] == "check_local_metadata" and calls == []


def test_linked_config_and_helper_never_followed(local):
    home, helper, calls = local
    path = config(home, [])
    outside = home / "other.json"
    outside.write_text('{"accounts":[]}')
    path.unlink()
    path.symlink_to(outside)
    assert (
        initialize(home, host_mail_state="none", provider="netease", configure=True)[
            "action"
        ]
        == "check_local_metadata"
    )
    path.unlink()
    helper.unlink()
    helper.symlink_to(outside)
    assert (
        initialize(home, host_mail_state="none", provider="netease", configure=True)[
            "action"
        ]
        == "review_helper"
    )
    assert calls == []


def test_missing_or_changed_helper_does_not_destroy_existing_account(local):
    home, helper, calls = local
    helper.unlink()
    assert (
        initialize(home, host_mail_state="none", provider="netease", configure=True)[
            "action"
        ]
        == "install_mail163"
    )
    config(home, ["synthetic@126.com"])
    assert initialize(home, configure=True)["action"] == "restore_helper"
    helper.write_text("# changed vendor code\n")
    assert initialize(home, configure=True)["action"] == "restore_helper"
    assert calls == []


def test_configuration_requires_opt_in_and_parallel_launches_are_deduplicated(local):
    home, _, calls = local
    params = {"host_mail_state": "none", "provider": "netease"}
    assert initialize(home, **params)["action"] == "ready_to_configure"
    assert calls == []
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: initialize(home, **params, configure=True)["action"], range(8)
            )
        )
    assert results.count("setup_started") == 1 and results.count("setup_pending") == 7
    argv = calls[0][0][0]
    assert argv[0] == sys.executable and argv[1] == "-I" and argv[-1] == "--run-helper"
    assert calls[0][1]["stdin"] == subprocess.DEVNULL
    assert calls[0][1]["stdout"] == subprocess.DEVNULL
    assert calls[0][1].get("shell", False) is False
    assert (
        initialize(home, **params, configure=True, retry=True)["action"]
        == "setup_started"
    )
    assert len(calls) == 2


def test_saving_during_initialization_prevents_new_window(local, monkeypatch):
    home, _, calls = local
    original = onboarding.local_mailbox
    count = 0

    def snapshot(root):
        nonlocal count
        count += 1
        if count == 2:
            config(home, ["synthetic@163.com"])
        return original(root)

    monkeypatch.setattr(onboarding, "local_mailbox", snapshot)
    result = initialize(
        home, host_mail_state="none", provider="netease", configure=True
    )
    assert result["action"] == "reuse_existing"
    assert result["local_mailbox"]["account_count"] == 1 and calls == []


def test_closed_gui_and_bad_state_directory_report_incomplete(local, monkeypatch):
    home, _, calls = local
    monkeypatch.setenv("MAIL163_NO_GUI", "1")
    assert (
        initialize(home, host_mail_state="none", provider="netease", configure=True)[
            "action"
        ]
        == "local_ui_unavailable"
    )
    monkeypatch.delenv("MAIL163_NO_GUI")
    state = home / "state/sentinel-security"
    state.rename(home / "previous-state")
    state.symlink_to(home / "previous-state", target_is_directory=True)
    assert (
        initialize(home, host_mail_state="none", provider="netease", configure=True)[
            "action"
        ]
        == "setup_unavailable"
    )
    assert calls == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_writable_and_fifo_metadata_fail_closed(local):
    home, _, calls = local
    path = config(home, [])
    path.chmod(0o666)
    assert onboarding.local_mailbox(home)["state"] == "unknown"
    path.unlink()
    os.mkfifo(path)
    assert onboarding.local_mailbox(home)["state"] == "unknown"
    assert calls == []


def test_helper_setup_enforces_certificate_and_hostname_verification(
    local, monkeypatch
):
    import imaplib

    home, helper, _ = local
    helper.write_text(
        "import imaplib\nimaplib.IMAP4_SSL('imap.163.com', 993, timeout=8)\n"
    )
    monkeypatch.setattr(
        onboarding, "MAIL163_SHA256", hashlib.sha256(helper.read_bytes()).hexdigest()
    )
    contexts = []

    class SyntheticIMAP:
        def __init__(self, *a, ssl_context=None, **kw):
            contexts.append(ssl_context)

    monkeypatch.setattr(imaplib, "IMAP4_SSL", SyntheticIMAP)
    previous_argv = sys.argv
    onboarding.run_reviewed_helper(home)
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED and contexts[0].check_hostname
    assert imaplib.IMAP4_SSL is SyntheticIMAP and sys.argv is previous_argv


def test_cli_inventory_and_installed_standalone_helper(local, monkeypatch):
    home, _, _ = local
    monkeypatch.setattr(Path, "home", lambda: home)
    config(home, ["synthetic@163.com"])
    output = inventory("workbuddy", [], True)
    assert output["services"][0]["service"] == "netease"
    assert output["services"][0]["category"] == "email"
    assert "synthetic@" not in json.dumps(output)
    root = home / "isolated-skills"
    install("workbuddy", root)
    script = root / "sentinel-security/scripts/workbuddy_bootstrap.py"
    # -I cannot import the source tree or site packages: the bundled file is self-contained.
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--help"], capture_output=True, check=True
    )
    assert b"--host-mail-state" in result.stdout
    source = Path(onboarding.__file__).read_text()
    bundled = Path(
        "integrations/workbuddy/connector/skills/sentinel-security/scripts/workbuddy_bootstrap.py"
    )
    assert bundled.read_text() == source


def test_manually_edited_helper_prevents_partial_skill_upgrade(tmp_path):
    root = tmp_path / "skills"
    skill = Path(install("workbuddy", root))
    script = skill.parent / "scripts/workbuddy_bootstrap.py"
    script.write_text("custom script\n")
    before = skill.read_bytes()
    with pytest.raises(ValueError):
        install("workbuddy", root)
    assert skill.read_bytes() == before and script.read_text() == "custom script\n"
