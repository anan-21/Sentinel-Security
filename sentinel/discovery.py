"""Build a scoped communication inventory from metadata supplied by the host."""

import re
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field

Host = Literal["workbuddy", "openclaw", "dsh", "muse", "generic"]
Name = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.-]{1,160}$")]
# Canonical service IDs only. Unknown aliases can be supplied separately by the host.
SERVICES = {
    "email": (
        "gmail",
        "outlook",
        "imap",
        "qqmail",
        "mail",
        "email",
        "protonmail",
        "netease",
        "mail163",
    ),
    "chat": (
        "whatsapp",
        "telegram",
        "discord",
        "slack",
        "teams",
        "imessage",
        "feishu",
        "lark",
        "dingtalk",
        "qq",
        "qqbot",
        "wechat",
        "wecom",
        "matrix",
        "signal",
    ),
    "web": ("browser", "web", "website", "webpage", "playwright", "chrome", "chromium"),
}
GROUP = {name: group for group, names in SERVICES.items() for name in names}
ACTIONS = {
    "search": {"search", "find", "query"},
    "read": {"get", "read", "fetch", "retrieve", "snapshot", "list", "history"},
    "send": {"send", "post", "reply", "forward"},
    "modify": {"modify", "update", "mark", "edit", "archive", "move"},
    "delete": {"delete", "remove", "trash"},
    "navigate": {"navigate", "open", "goto"},
}


class Observation(BaseModel):
    """Only identifiers and explicit operation metadata. Never send raw tool config."""

    model_config = ConfigDict(extra="forbid")
    name: Name
    kind: Literal["tool", "registered", "configured", "previously_seen"] = "tool"
    service: Name | None = None
    availability: Literal["unknown", "enabled", "disabled", "revoked"] = "unknown"
    category: Literal["email", "chat", "web", "other"] | None = None


class Inventory(BaseModel):
    host: Host
    services: list[dict]
    ignored: int
    coverage: str = "仅列出本次输入可见的元数据。配置和工具名称不能证明账户授权；缺失的历史连接未知。"


def tokens(value: str) -> list[str]:
    split = re.sub(r"([a-z])([A-Z])", r"\1_\2", value)
    return re.findall(r"[a-z0-9]+", split.lower())


def discover(host: Host, observations: list[Observation]) -> Inventory:
    groups = {}
    ignored = 0
    for item in observations:
        parts = tokens(item.name)
        if item.name.startswith("sentinel_") or "sentinel" in parts:
            ignored += 1
            continue
        if "qq" in parts and ("mail" in parts or "email" in parts):
            parts.insert(0, "qqmail")
        provider = item.service or next((p for p in parts if p in GROUP), None)
        if not provider and item.kind in {"configured", "previously_seen"}:
            provider = item.name
        if not provider and item.category:
            provider = item.name
        if not provider:
            ignored += 1
            continue
        provider = provider.lower()
        if provider == "mail163":
            provider = "netease"
        entry = groups.setdefault(
            provider,
            {
                "service": provider,
                "category": item.category or GROUP.get(provider, "other"),
                "evidence": set(),
                "reported_availability": set(),
                "tools": set(),
                "operations": set(),
                "authorization": "unknown",
                "background": "unverified",
            },
        )
        entry["evidence"].add(
            {
                "tool": "tool_visible",
                "registered": "registered",
                "configured": "configured",
                "previously_seen": "historical",
            }[item.kind]
        )
        if item.availability != "unknown":
            entry["reported_availability"].add(item.availability)
        if item.kind == "tool":
            entry["tools"].add(item.name)
            entry["operations"].update(
                op for op, words in ACTIONS.items() if words.intersection(parts)
            )
    rows = []
    for name in sorted(groups):
        row = groups[name]
        states = row["reported_availability"]
        ops = row["operations"]
        row["suggested_scanner"] = {
            "web": "sentinel_scan_webpage",
            "email": "sentinel_scan_message",
            "chat": "sentinel_scan_message",
        }.get(row["category"])
        if states & {"revoked", "disabled"}:
            row["next_step"] = "暂停；宿主报告禁用或撤权。"
        elif row["suggested_scanner"] and "read" in ops:
            row["next_step"] = "使用已授权测试项验证只读内容范围，再按需检测。"
        elif row["evidence"] == {"historical"}:
            row["next_step"] = "仅有历史记录，检查当前绑定状态。"
        else:
            row["next_step"] = "在当前宿主核对可读取的内容和授权。"
        rows.append({k: sorted(v) if isinstance(v, set) else v for k, v in row.items()})
    return Inventory(host=host, services=rows, ignored=ignored)
