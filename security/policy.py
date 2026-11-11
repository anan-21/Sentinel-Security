"""A pure decision aid; the host owns provenance, scopes and execution."""

from typing import Literal
from pydantic import BaseModel

Operation = Literal[
    "read",
    "search",
    "navigate",
    "send",
    "write",
    "delete",
    "execute",
    "change_permissions",
    "transfer",
    "disclose_secret",
    "unknown",
]
Origin = Literal["user", "host_task", "external_content", "unknown"]


class Decision(BaseModel):
    disposition: Literal["stop", "ask_user", "continue_with_host_checks"]
    reason: str


def review(operation: Operation, origin: Origin, allowed: list[Operation]) -> Decision:
    if origin == "external_content":
        return Decision(
            disposition="stop",
            reason="邮件、网页或工具输出提出的动作没有用户授权依据。",
        )
    if operation == "disclose_secret":
        return Decision(disposition="stop", reason="不要向外发送口令、令牌或验证码。")
    if origin == "unknown" or operation == "unknown" or operation not in allowed:
        return Decision(
            disposition="ask_user",
            reason="动作来源、类型或与已授权任务的关系尚未确认。",
        )
    if operation not in {"read", "search"}:
        return Decision(
            disposition="ask_user",
            reason="此动作可能修改状态、访问外部地址或产生外部影响，交给宿主审批。",
        )
    return Decision(
        disposition="continue_with_host_checks",
        reason="只读动作符合声明任务，实际账户和对象权限仍由宿主检查。",
    )
