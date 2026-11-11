import logging
from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp.server.transport_security import TransportSecuritySettings
from security.engine import scan, report, url_findings, finding
from server.schemas import Report
from security.policy import review, Decision, Operation, Origin
from sentinel.discovery import Host, Inventory, Observation, discover
from server.auth import Guard
import os

Text = Annotated[str, Field(max_length=100000)]
URL = Annotated[str, Field(max_length=4096)]
mcp = FastMCP(
    "Sentinel Security",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        allowed_hosts=os.environ.get(
            "SENTINEL_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*"
        ).split(",")
    ),
)
a = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


@mcp.tool(annotations=a)
def sentinel_scan_message(
    source: str,
    sender: Text,
    subject: Text,
    body: Text,
    links: Annotated[list[URL], Field(max_length=50)] = [],
) -> Report:
    """Analyze untrusted message content without fetching URLs or saving content."""
    return scan({"sender": sender, "subject": subject, "body": body}, links)


@mcp.tool(annotations=a)
def sentinel_scan_url(url: URL) -> Report:
    """Static URL analysis only. No DNS, network requests or threat intelligence."""
    return report(url_findings(url))


@mcp.tool(annotations=a)
def sentinel_scan_webpage(url: URL, text: Text) -> Report:
    """Analyze supplied page text; does not browse or execute content."""
    return scan({"text": text}, [url])


@mcp.tool(annotations=a)
def sentinel_scan_action(action: Text, user_goal: Text = "") -> Report:
    """Advisory action review, never grants permission or executes actions."""
    r = scan({"action": action})
    import re

    m = re.search(
        r"transfer|send email|change permissions|转账|发送邮件|修改权限|grant access",
        action,
        re.I,
    )
    if m:
        r.findings.append(
            finding(
                "sensitive_action",
                "需要宿主原生审批；不能据描述认定已获授权",
                "action",
                action,
                m.start(),
                m.end(),
            )
        )
    if m and (
        goal_match := re.search(
            r"(?:只|仅)(?:需|允许)?(?:读|查看|总结|检索|搜索|起草)|(?:only|just)\s+(?:read|summari[sz]e|search|draft)",
            user_goal,
            re.I,
        )
    ):
        r.findings.append(
            finding(
                "goal_conflict",
                "用户目标限定为只读或草稿，拟执行动作有外部影响。",
                "user_goal",
                user_goal,
                goal_match.start(),
                goal_match.end(),
                "HIGH",
            )
        )
    result = report(r.findings)
    result.uncertainty.append("无法可靠判断操作与用户目标的语义一致性；由宿主核对。")
    return result


@mcp.tool(annotations=a)
def sentinel_discover(
    host: Host, observations: Annotated[list[Observation], Field(max_length=512)]
) -> Inventory:
    """Summarize host-supplied identifiers. Never supply credentials, configuration or content."""
    return discover(host, observations)


@mcp.tool(annotations=a)
def sentinel_review_tool_call(
    operation: Operation,
    origin: Origin,
    allowed_operations: Annotated[list[Operation], Field(max_length=16)],
) -> Decision:
    """Check a proposed operation against its trusted origin and user task. Never executes it."""
    return review(operation, origin, allowed_operations)


@mcp.tool(annotations=a)
def sentinel_scan_prompt(text: Text) -> Report:
    """Inspect untrusted tool output, messages or text for indirect prompt injection."""
    return scan({"text": text})


@mcp.tool(annotations=a)
def sentinel_get_status() -> dict:
    """Service capabilities, not Muse connector discovery or monitoring status."""
    return {
        "version": "0.2.0",
        "healthy": True,
        "modules": [
            "message",
            "url",
            "webpage",
            "action",
            "prompt",
            "discovery",
            "tool_policy",
        ],
        "network_fetch": False,
        "content_storage": False,
        "monitoring": "host-managed; unverified",
        "threat_intelligence": False,
    }


def create_app():
    return Guard(mcp.streamable_http_app())


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(
        create_app(),
        host=os.environ.get("SENTINEL_BIND", "127.0.0.1"),
        port=8000,
        access_log=False,
    )
