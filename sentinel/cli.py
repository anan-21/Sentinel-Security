"""Local installation and read-only checks. Content is read exclusively from stdin."""

import argparse
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from importlib.resources import files
from pydantic import ValidationError, TypeAdapter
from .discovery import discover, Observation
from .history import recall, forget
from .openclaw import local_channels
from .workbuddy import configured_connectors

INSTALL_HOSTS = ("openclaw", "dsh", "workbuddy")


def install(host, root=None):
    # Default to a per-user skill directory. An explicit root enables isolated setups.
    if root is None:
        roots = {
            "openclaw": Path.home() / ".openclaw" / "skills",
            "dsh": Path(os.environ.get("DSH_HOME", Path.home() / ".dsh")) / "skills",
            "workbuddy": Path.home() / ".workbuddy" / "skills",
        }
        root = roots[host]
    dest = Path(root) / "sentinel-security" / "SKILL.md"
    if dest.parent.is_symlink() or dest.is_symlink():
        raise ValueError("安装目标是符号链接；请选择实际目录。")
    dest.parent.mkdir(parents=True, exist_ok=True)
    resource = files("sentinel").joinpath("SKILL.md")
    if not resource.is_file():
        resource = Path(__file__).resolve().parents[1] / "SKILL.md"

    def marker(content):
        checksum = hashlib.sha256(content.encode("utf8")).hexdigest()
        return f"<!-- installed by sentinel-security for {host}: {checksum} -->"

    content = resource.read_text(encoding="utf8").replace("HOST_ARGUMENT", host) + "\n"
    body = content + marker(content) + "\n"
    if dest.exists():
        old = dest.read_text(encoding="utf8")
        if old == body:
            return str(dest)
        prior, sep, footer = old.removesuffix("\n").rpartition("\n")
        if not sep or footer != marker(prior + sep):
            raise ValueError("已有同名 Skill 或本地编辑；请选择空目录。")
    with tempfile.NamedTemporaryFile(
        dir=dest.parent, delete=False, mode="w", encoding="utf8"
    ) as tmp:
        tmp.write(body)
    os.replace(tmp.name, dest)
    return str(dest)


def read_json():
    payload = sys.stdin.buffer.read(262145)
    if len(payload) > 262144:
        raise ValueError("input too large")
    return json.loads(payload)


def run(args):
    if args.command == "install":
        target = install(args.host, args.skills_root)
        # Installation always inventories the local host evidence that is safe to collect.
        return {
            "installed": target,
            **inventory(args.host, [], True, args.workbuddy_profile),
        }
    if args.command == "discover":
        observations = (
            TypeAdapter(list[Observation]).validate_python(read_json())
            if args.stdin
            else []
        )
        if len(observations) > 512:
            raise ValueError("at most 512 observations")
        result = inventory(
            args.host, observations, not args.no_local, args.workbuddy_profile
        )
        if args.remember:
            result["previously_configured_not_observed"] = recall(
                args.host, args.remember, result["services"]
            )
        return result
    if args.command == "forget":
        forget(args.host, args.profile)
        return {"forgotten": True}
    if args.command == "mcp":
        from server.mcp_server import mcp

        mcp.run(transport="stdio")
        return None
    from server.mcp_server import (
        sentinel_scan_message,
        sentinel_scan_url,
        sentinel_scan_webpage,
        sentinel_scan_action,
        sentinel_scan_prompt,
        sentinel_review_tool_call,
    )
    from pydantic import validate_call

    fn = {
        "message": sentinel_scan_message,
        "url": sentinel_scan_url,
        "webpage": sentinel_scan_webpage,
        "action": sentinel_scan_action,
        "prompt": sentinel_scan_prompt,
        "tool-call": sentinel_review_tool_call,
    }[args.kind]
    payload = read_json()
    if not isinstance(payload, dict):
        raise ValueError("expected an object")
    return validate_call(fn)(**payload).model_dump()


def inventory(host, observations, collect, wb_profile=None):
    notices = []
    if host == "workbuddy" and collect:
        profile = wb_profile or os.environ.get("SENTINEL_WORKBUDDY_PROFILE")
        if profile:
            try:
                observations = [*observations, *configured_connectors(profile)]
            except (OSError, ValueError):
                notices.append(
                    "所选 WorkBuddy 配置不可读或版本未知，请使用原生连接器查询。"
                )
    if host == "openclaw" and collect:
        try:
            observations = [*observations, *local_channels()]
        except (OSError, ValueError, subprocess.SubprocessError):
            notices.append("OpenClaw 渠道枚举失败；请使用当前会话工具清单补充。")
    if host in ("workbuddy", "dsh", "muse", "generic") and not observations:
        notices.append("等待当前宿主会话提供可见工具。空清单不代表没有连接。")
    return {**discover(host, observations).model_dump(), "notices": notices}


def main():
    parser = argparse.ArgumentParser(prog="sentinel-security")
    sub = parser.add_subparsers(dest="command", required=True)
    ins = sub.add_parser("install")
    ins.add_argument("host", choices=INSTALL_HOSTS)
    ins.add_argument("--skills-root", type=Path)
    disc = sub.add_parser("discover")
    disc.add_argument("host", choices=(*INSTALL_HOSTS, "muse", "generic"))
    disc.add_argument(
        "--stdin",
        action="store_true",
        help="read sanitized observation array from stdin",
    )
    disc.add_argument(
        "--no-local", action="store_true", help="only classify supplied evidence"
    )
    disc.add_argument(
        "--remember",
        metavar="PROFILE",
        help="remember configured service identifiers locally",
    )
    clear = sub.add_parser("forget")
    clear.add_argument("host", choices=(*INSTALL_HOSTS, "muse", "generic"))
    clear.add_argument("profile")
    for command in (ins, disc):
        command.add_argument(
            "--workbuddy-profile",
            help="project only bound/enabled flags of this WorkBuddy profile",
        )
    scan = sub.add_parser("scan")
    scan.add_argument(
        "kind", choices=("message", "webpage", "url", "prompt", "action", "tool-call")
    )
    sub.add_parser("mcp")
    try:
        result = run(parser.parse_args())
    except (ValueError, OSError, ValidationError, TypeError):
        parser.exit(2, "无法处理该请求。请检查输入结构、长度、安装目录及文件权限。\n")
    if result is not None:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
