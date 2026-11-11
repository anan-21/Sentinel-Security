"""Bounded, local checks on an untrusted text field, with original-string offsets."""

import base64
import binascii
import html
import re
import unicodedata

from server.schemas import Finding

RULES = [
    (
        "override_zh",
        r"(?:忽略|无视|覆盖|忘掉|撤销).{0,10}(?:系统|开发者|先前|之前|此前|上面).{0,5}(?:指令|提示|规则|约束)",
        "要求忽略或覆盖原有安全指令",
    ),
    (
        "memory_override",
        r"(?:记住|保存到记忆).{0,30}(?:以后|从现在起).{0,20}(?:不用|无需|跳过).{0,8}(?:审批|确认|授权)",
        "诱导修改以后任务的授权策略",
    ),
    (
        "override",
        r"(?:disregard|forget|override|ignore)\s+(?:(?:all|the|your|any)\s+)?(?:previous|prior|earlier|system|safety|developer)\s+(?:guidance|instructions?|rules?|policy|messages?)",
        "试图替换宿主指令",
    ),
    (
        "authority",
        r"<\|(?:im_start\|>\s*(?:system|developer)|(?:system|developer)\|>)|\[/?INST\]|</?(?:system_instruction|developer_message)>",
        "外部内容伪造指令边界",
    ),
    (
        "persistence",
        r"(?:永久记住|写入.{0,5}(?:记忆|memory)|remember permanently|save (?:this|it) to memory).{0,65}(?:指令|忽略|无需批准|always trust|skip approval|ignore)",
        "要求把不可信指令写入长期记忆",
    ),
    (
        "exfiltration",
        r"(?:deliver|upload|forward|export|send)\s+(?:(?:the|my|your|all|entire|full)\s+){0,3}(?:correspondence archive|address book|private keys?|mailbox archive|oauth tokens?)",
        "要求导出私人数据或凭据",
    ),
    (
        "tool_coercion",
        r"(?:without (?:the )?(?:user approval|confirmation)|无需(?:用户)?(?:确认|审批)|别告诉用户).{0,50}(?:执行|发送|调用|上传|send|execute|call)|(?:call|run|invoke)\s+(?:the\s+)?(?:shell|terminal|send_email).{0,64}without (?:asking|approval)",
        "要求跳过用户确认执行工具",
    ),
]
PATTERNS = [(k, re.compile(p, re.I | re.S), reason) for k, p, reason in RULES]
ENTITY = re.compile(r"&(?:#(?:[0-9]{1,7}|x[0-9a-fA-F]{1,6})|[A-Za-z]{2,20});")


def normalized(text):
    chars, starts, ends = [], [], []
    i = 0
    while i < len(text):
        ent = ENTITY.match(text, i) if text[i] == "&" else None
        end = ent.end() if ent else i + 1
        chunk = html.unescape(ent.group()) if ent else text[i]
        for char in unicodedata.normalize("NFKC", chunk):
            if unicodedata.category(char) == "Cf":
                continue
            chars.append(char)
            starts.append(i)
            ends.append(end)
        i = end
    return "".join(chars), starts, ends


def inspect(text, field):
    value, starts, ends = normalized(text)
    result = []
    for family, pattern, reason in PATTERNS:
        match = pattern.search(value)
        if match:
            start, end = starts[match.start()], ends[match.end() - 1]
            result.append(
                Finding(
                    type="injection_" + family,
                    reason=reason,
                    field=field,
                    evidence=text[start:end],
                    start=start,
                    end=end,
                    severity="HIGH",
                )
            )
    # Inspect explicitly marked base64 once. Never execute or return the decoded bytes.
    for index, encoded in enumerate(
        re.finditer(
            r"(?i)\bbase64[,:=]\s*([A-Za-z0-9+/]{12,2048}={0,2})(?![A-Za-z0-9+/=])",
            value,
        )
    ):
        if index >= 8:
            break
        try:
            decoded = base64.b64decode(encoded[1], validate=True).decode("utf-8")
        except (ValueError, binascii.Error):
            continue
        decoded_value, _, _ = normalized(decoded)
        if any(pattern.search(decoded_value) for _, pattern, _ in PATTERNS):
            start, end = starts[encoded.start()], ends[encoded.end() - 1]
            result.append(
                Finding(
                    type="injection_encoded",
                    reason="显式标记的编码文本解码后命中注入规则",
                    field=field,
                    evidence="[编码片段已隐藏]",
                    start=start,
                    end=end,
                    severity="HIGH",
                )
            )
            break
    return result
