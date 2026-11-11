"""Local WorkBuddy mailbox onboarding. Also distributable as a standalone skill script.

Discovery never runs the mail helper or opens the credential store. Only an
explicit configuration invocation can start the reviewed, installed helper.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

# Audited WorkBuddy marketplace mail163 1.5.2. New code must be reviewed before
# automatically executing it; the third-party helper is not redistributed here.
MAIL163_SHA256 = "dd19f8394dabb562ea538b5989307359967e40ddae95615da923cb64e635d5d7"
DOMAINS = {"163.com", "126.com", "yeah.net", "188.com", "vip.163.com", "vip.126.com"}


def safe_file(path, base, limit):
    """Reject linked, non-regular, foreign-owned or writable-by-others inputs."""
    path, base = Path(path), Path(base)
    parts = path.relative_to(base).parts
    cursor = base
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("linked metadata")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("unsupported metadata")
        if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError("unsafe metadata permissions")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("metadata too large")
    return data


def local_mailbox(home=None):
    home = Path(home or Path.home())
    result = {
        "state": "absent",
        "account_count": 0,
        "cached_verified_count": 0,
        "helper": "missing",
        "authorization": "unverified",
    }
    path = home / ".wb-163-mail" / "config.json"
    try:
        raw = json.loads(safe_file(path, home, 65536))
        accounts = raw.get("accounts") if isinstance(raw, dict) else None
        if not isinstance(accounts, list) or len(accounts) > 64:
            raise ValueError("unknown account format")
        for account in accounts:
            if (
                not isinstance(account, str)
                or len(account) > 254
                or not re.fullmatch(r"[A-Za-z0-9._%+-]+@[^@\s]+", account)
                or account.rsplit("@", 1)[1].lower() not in DOMAINS
            ):
                raise ValueError("unknown account format")
        if len(set(accounts)) != len(accounts):
            raise ValueError("duplicate account metadata")
        if raw.get("default") is not None and raw["default"] not in accounts:
            raise ValueError("unknown default account")
        info = raw.get("info", {})
        if not isinstance(info, dict):
            raise ValueError("unknown verification metadata")
        result["account_count"] = len(accounts)
        result["cached_verified_count"] = sum(
            isinstance(info.get(account), dict)
            and info[account].get("verified") is True
            for account in accounts
        )
        result["state"] = "configured" if accounts else "absent"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, RecursionError):
        result["state"] = "unknown"
    helper = home / ".workbuddy" / "skills" / "mail163" / "scripts" / "mail163.py"
    try:
        digest = hashlib.sha256(safe_file(helper, home, 2 * 1024 * 1024)).hexdigest()
        result["helper"] = "reviewed" if digest == MAIL163_SHA256 else "unverified"
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        result["helper"] = "unverified"
    return result


def _launch(home, retry, state_home=None):
    root = Path(state_home or os.environ.get("XDG_STATE_HOME") or home / ".local/state")
    folder = root / "sentinel-security"
    if folder.is_symlink():
        raise ValueError("linked setup state")
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / "workbuddy-mail-setup.sqlite"
    if path.is_symlink():
        raise ValueError("linked setup state")
    descriptor = os.open(
        path, os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    os.close(descriptor)
    # One transaction covers checking and recording the launch. Parallel agent
    # sessions cannot open two configuration windows. Cancellation needs --retry.
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "CREATE TABLE IF NOT EXISTS attempt(id INTEGER PRIMARY KEY, started REAL)"
        )
        if db.execute("SELECT 1 FROM attempt WHERE id=1").fetchone() and not retry:
            return "setup_pending"
        if os.environ.get("MAIL163_NO_GUI"):
            return "local_ui_unavailable"
        helper = home / ".workbuddy/skills/mail163/scripts/mail163.py"
        # Recheck immediately before execution. Content and arguments never come
        # from a message, a webpage, the metadata file or a tool description.
        current = local_mailbox(home)
        if current["state"] == "configured":
            return "reuse_existing"
        if current["state"] == "unknown":
            return "check_local_metadata"
        if current["helper"] != "reviewed":
            return "review_helper"
        subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--run-helper"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(helper.parent),
            close_fds=True,
            start_new_session=os.name == "posix",
        )
        db.execute("INSERT OR REPLACE INTO attempt VALUES(1, ?)", (time.time(),))
    return "setup_started"


def run_reviewed_helper(home=None):
    """Run only the reviewed setup code, with authenticated IMAP TLS enforced.

    IMAP4_SSL's stdlib default does not enable certificate verification. Keep
    the marketplace helper unchanged and supply a verified context in this
    isolated setup process instead.
    """
    import imaplib
    import runpy
    import ssl

    home = Path(home or Path.home())
    if local_mailbox(home)["helper"] != "reviewed":
        raise ValueError("mail helper not reviewed")
    original = imaplib.IMAP4_SSL
    context = ssl.create_default_context()

    class VerifiedIMAP(original):
        def __init__(self, *args, **kwargs):
            kwargs["ssl_context"] = context
            super().__init__(*args, **kwargs)

    previous = sys.argv
    helper = home / ".workbuddy/skills/mail163/scripts/mail163.py"
    try:
        imaplib.IMAP4_SSL = VerifiedIMAP
        sys.argv = [str(helper), "setup", "--timeout", "900"]
        runpy.run_path(str(helper), run_name="__main__")
    finally:
        imaplib.IMAP4_SSL = original
        sys.argv = previous


def bootstrap(
    *,
    host_mail_state="unknown",
    provider=None,
    configure=False,
    retry=False,
    home=None,
    state_home=None,
):
    if host_mail_state not in {"unknown", "none", "present", "blocked"}:
        raise ValueError("invalid host mailbox state")
    if provider not in {None, "netease"}:
        raise ValueError("unsupported setup provider")
    if retry and not configure:
        raise ValueError("retry requires configure")
    home = Path(home or Path.home())
    local = local_mailbox(home)
    result = {
        "host": "workbuddy",
        "local_mailbox": local,
        "host_mail_state": host_mail_state,
        "authorization": "unverified",
        "monitoring": "not_started",
    }
    if host_mail_state == "blocked":
        action = "review_permissions"
    elif local["state"] == "unknown":
        action = "check_local_metadata"
    elif local["state"] == "configured":
        action = "reuse_existing" if local["helper"] == "reviewed" else "restore_helper"
    elif host_mail_state == "present":
        action = "verify_existing"
    elif host_mail_state == "unknown":
        action = "query_host_inventory"
    elif not provider:
        action = "choose_provider"
    elif local["helper"] == "missing":
        action = "install_mail163"
    elif local["helper"] != "reviewed":
        action = "review_helper"
    elif not configure:
        action = "ready_to_configure"
    else:
        try:
            action = _launch(home, retry, state_home)
            result["local_mailbox"] = local_mailbox(home)
        except (OSError, ValueError, sqlite3.Error):
            action = "setup_unavailable"
    result["action"] = action
    result["next_step"] = {
        "reuse_existing": "复用本机已配置的网易邮箱；缓存验证不代表本次登录成功，不重新配置。",
        "restore_helper": "本机有邮箱记录，先恢复或核对邮件助手；不要重新创建账号。",
        "verify_existing": "当前宿主有邮箱证据，核对已授权范围并复用；不要另开配置。",
        "review_permissions": "宿主报告禁用或撤权，先处理原有连接；不要用新配置绕过。",
        "check_local_metadata": "本机邮箱状态未知，先检查配置文件的格式和权限；不视为未连接。",
        "query_host_inventory": "先查询当前 WorkBuddy 的连接器及可见邮箱工具；未知不能当作没有。",
        "choose_provider": "已检查的范围未发现邮箱，请用户选择邮箱服务商，不默认创建网易账号。",
        "install_mail163": "通过 WorkBuddy 原生技能市场安装“163邮箱助手”，再运行本初始化命令。",
        "review_helper": "已安装邮件助手与审核过的版本不一致；先审核代码，不自动执行。",
        "ready_to_configure": "已确认此范围未配置邮箱；使用 --configure 打开本机向导。",
        "setup_started": "已启动本机配置向导，用户在页面输入授权码并保存；之后重新初始化核验。",
        "setup_pending": "本次配置已发起，不重复弹窗；用户明确要求重试时加 --retry。",
        "local_ui_unavailable": "当前环境关闭了本机界面；在可交互的 WorkBuddy 客户端继续配置。",
        "setup_unavailable": "配置向导未能启动，请检查本机权限；不代表已连接。",
    }[action]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host-mail-state",
        choices=["unknown", "none", "present", "blocked"],
        default="unknown",
    )
    parser.add_argument("--provider", choices=["netease"])
    parser.add_argument("--configure", action="store_true")
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--run-helper", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.run_helper:
            run_reviewed_helper()
            return
        result = bootstrap(
            host_mail_state=args.host_mail_state,
            provider=args.provider,
            configure=args.configure,
            retry=args.retry,
        )
    except ValueError:
        parser.error("初始化参数不一致。")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
